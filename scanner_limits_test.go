package portscan

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestScan_ConcurrencyIsLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: 10 * time.Millisecond}
		s := newTestScanner(t, d, nil, WithConcurrency(5))

		start := time.Now()
		results := collect(mustScan(t, s, bg, []string{"10.0.0.1"}, Range(1, 50)))

		if len(results) != 50 {
			t.Fatalf("результатов %d, want 50", len(results))
		}
		if d.maxInFlight != 5 {
			t.Errorf("одновременно %d подключений, want 5", d.maxInFlight)
		}
		// 50 проверок по 5 за раз: 10 партий по 10мс, лимит не простаивает
		if elapsed := time.Since(start); elapsed != 100*time.Millisecond {
			t.Errorf("заняло %v, want 100ms", elapsed)
		}
	})
}

func TestScan_FewerJobsThanConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: 10 * time.Millisecond}
		s := newTestScanner(t, d, nil, WithConcurrency(100))
		results := collect(mustScan(t, s, bg, []string{"10.0.0.1"}, Ports(80, 81, 82)))
		if len(results) != 3 || d.maxInFlight != 3 {
			t.Errorf("results = %d, maxInFlight = %d, want 3 и 3", len(results), d.maxInFlight)
		}
	})
}

func TestScan_LimitIsSharedBetweenScans(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: 10 * time.Millisecond}
		s := newTestScanner(t, d, nil, WithConcurrency(4))

		ch1 := mustScan(t, s, bg, []string{"10.0.0.1"}, Range(1, 20))
		ch2 := mustScan(t, s, bg, []string{"10.0.0.2"}, Range(1, 20))

		// второй Scan пока никто не читает: первый обязан дойти до конца,
		// то есть ждущие читателя результаты не держат слоты
		r1 := collect(ch1)
		r2 := collect(ch2)

		if len(r1) != 20 || len(r2) != 20 {
			t.Errorf("результатов %d и %d, want 20 и 20", len(r1), len(r2))
		}
		if d.maxInFlight != 4 {
			t.Errorf("одновременно %d подключений на двух Scan, want 4", d.maxInFlight)
		}
	})
}

func TestScan_ResolvingParallelismIsLimited(t *testing.T) {
	tests := []struct {
		name        string
		concurrency int
		want        int
	}{
		{"лимит сканера больше предела DNS", 100, maxResolveWorkers},
		{"лимит сканера меньше предела DNS", 3, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				answers := map[string]answer{}
				var hosts []string
				for i := range 40 {
					h := "n" + string(rune('a'+i/26)) + string(rune('a'+i%26)) + ".example"
					hosts = append(hosts, h)
					answers[h] = answer{addrs: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})}, delay: 10 * time.Millisecond}
				}
				r := &fakeResolver{answers: answers}
				s := newTestScanner(t, &fakeDialer{}, r, WithConcurrency(tt.concurrency))

				results := collect(mustScan(t, s, bg, hosts, Ports(80)))

				if len(results) != 40 {
					t.Fatalf("результатов %d, want 40", len(results))
				}
				if r.maxInFlight != tt.want {
					t.Errorf("одновременно %d DNS-запросов, want %d", r.maxInFlight, tt.want)
				}
			})
		})
	}
}

func TestCheck_SlotIsHeldOnlyWhileDialing(t *testing.T) {
	var s *Scanner
	d := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		if n := len(s.sem); n != 1 {
			t.Errorf("во время подключения занято слотов %d, want 1", n)
		}
		return nil, dialErr(syscall.ECONNREFUSED)
	})
	s = newTestScanner(t, d, nil, WithConcurrency(3))

	res, ok := s.check(bg, job{ep: endpoint{"a", addr("10.0.0.1")}, port: 80})
	if !ok || res.State != StateClosed {
		t.Errorf("check = %+v, %v", res, ok)
	}
	if n := len(s.sem); n != 0 {
		t.Errorf("после проверки занято слотов %d, want 0", n)
	}
}

func TestScan_SlowReaderSlowsDownTheScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(4))
		ch := mustScan(t, s, bg, []string{"10.0.0.1"}, Range(1, 1000))

		time.Sleep(time.Second) // читатель молчит
		synctest.Wait()

		// в буфере 4 результата и ещё по одному у каждого из 4 воркеров
		if started := d.started(); started < 4 || started > 8 {
			t.Errorf("пока никто не читает, начато %d подключений, want от 4 до 8", started)
		}

		// читатель проснулся: все результаты на месте
		if n := len(collect(ch)); n != 1000 {
			t.Errorf("результатов %d, want 1000", n)
		}
	})
}

func TestScan_ConcurrentScansOnOneScanner(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: time.Millisecond, open: func(ap netip.AddrPort) bool { return ap.Port()%2 == 0 }}
		s := newTestScanner(t, d, nil, WithConcurrency(6))

		const scans = 8
		var wg sync.WaitGroup
		for i := range scans {
			wg.Go(func() {
				ip := netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)})
				results := collect(mustScan(t, s, bg, []string{ip.String()}, Range(1, 200)))
				if len(results) != 200 {
					t.Errorf("scan %d: результатов %d, want 200", i, len(results))
				}
				for _, r := range results {
					if r.IP != ip {
						t.Errorf("scan %d: чужой результат %+v", i, r)
						return
					}
				}
				byAddr(t, results)
			})
		}
		wg.Wait()

		if d.maxInFlight > 6 {
			t.Errorf("одновременно %d подключений, лимит 6", d.maxInFlight)
		}
		if d.started() != scans*200 {
			t.Errorf("подключений %d, want %d", d.started(), scans*200)
		}
	})
}

func TestScan_ManyHostsAndAllPorts(t *testing.T) {
	if testing.Short() {
		t.Skip("131070 проверок, под -race это около двух секунд")
	}
	d := &fakeDialer{open: func(ap netip.AddrPort) bool { return ap.Port() == 443 }}
	s := newTestScanner(t, d, nil, WithConcurrency(100))

	hosts := []string{"10.0.0.1", "10.0.0.2"}
	got := byAddr(t, collect(mustScan(t, s, bg, hosts, Range(1, 65535))))

	if len(got) != 2*65535 {
		t.Fatalf("результатов %d, want %d", len(got), 2*65535)
	}
	for k, r := range got {
		if (r.State == StateOpen) != (r.Port == 443) {
			t.Fatalf("%s: State = %v", k, r.State)
		}
	}
}
