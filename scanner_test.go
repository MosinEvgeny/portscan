package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// fakeDialer подменяет сеть: считает вызовы, держит подключения заданное время
// и отвечает "открыт" или "отказ" по правилу open.
type fakeDialer struct {
	delay time.Duration
	hang  bool                      // висит, пока не истечёт контекст попытки
	open  func(netip.AddrPort) bool // nil - все порты закрыты

	mu          sync.Mutex
	calls       []string // адреса в порядке начала подключения
	inFlight    int
	maxInFlight int
	conns       []*fakeConn
}

func (d *fakeDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.calls = append(d.calls, address)
	d.inFlight++
	d.maxInFlight = max(d.maxInFlight, d.inFlight)
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		d.inFlight--
		d.mu.Unlock()
	}()

	if d.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if ap, err := netip.ParseAddrPort(address); err == nil && d.open != nil && d.open(ap) {
		c := &fakeConn{}
		d.mu.Lock()
		d.conns = append(d.conns, c)
		d.mu.Unlock()
		return c, nil
	}
	return nil, dialErr(syscall.ECONNREFUSED)
}

func (d *fakeDialer) started() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.calls)
}

func newTestScanner(t *testing.T, d Dialer, r Resolver, opts ...Option) *Scanner {
	t.Helper()
	all := []Option{WithDialer(d)}
	if r != nil {
		all = append(all, WithResolver(r))
	}
	s, err := New(append(all, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustScan(t *testing.T, s *Scanner, ctx context.Context, hosts []string, ports PortSet) <-chan Result {
	t.Helper()
	ch, err := s.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return ch
}

func collect(ch <-chan Result) []Result {
	var rs []Result
	for r := range ch {
		rs = append(rs, r)
	}
	return rs
}

// byAddr раскладывает результаты по "адрес:порт", повторы считает ошибкой
func byAddr(t *testing.T, results []Result) map[string]Result {
	t.Helper()
	m := make(map[string]Result, len(results))
	for _, r := range results {
		k := netip.AddrPortFrom(r.IP, r.Port).String()
		if _, dup := m[k]; dup {
			t.Errorf("%s проверен больше одного раза", k)
		}
		m[k] = r
	}
	return m
}

func count(results []Result, s State) int {
	n := 0
	for _, r := range results {
		if r.State == s {
			n++
		}
	}
	return n
}

var bg = context.Background()

// ---- ошибки до старта ----

func TestScan_InvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		hosts []string
		ports PortSet
		want  []error
	}{
		{"нет хостов", nil, Ports(80), []error{ErrNoTargets}},
		{"пустой хост", []string{""}, Ports(80), []error{ErrEmptyHost}},
		{"кривой хост", []string{"bad host"}, Ports(80), []error{ErrInvalidHost}},
		{"нет портов", []string{"10.0.0.1"}, PortSet{}, []error{ErrNoPorts}},
		{"порт 0", []string{"10.0.0.1"}, Ports(0), []error{ErrInvalidPort}},
		{"обратный диапазон", []string{"10.0.0.1"}, Range(1000, 1), []error{ErrInvalidRange}},
		{"плохо и хосты, и порты", []string{"bad host"}, Ports(70000), []error{ErrInvalidHost, ErrInvalidPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// synctest заодно проверяет, что Scan не оставил горутин
			synctest.Test(t, func(t *testing.T) {
				d, r := &fakeDialer{}, &fakeResolver{}
				s := newTestScanner(t, d, r)
				ch, err := s.Scan(bg, tt.hosts, tt.ports)
				if ch != nil {
					t.Error("вместе с ошибкой вернулся канал")
				}
				for _, want := range tt.want {
					if !errors.Is(err, want) {
						t.Errorf("error = %v, want %v", err, want)
					}
				}
				if d.started() != 0 || len(r.calls) != 0 {
					t.Error("при ошибке скан не должен был начаться")
				}
			})
		})
	}
}

func TestScan_ContextAlreadyDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil)

		canceled, cancel := context.WithCancel(bg)
		cancel()
		expired, cancel2 := context.WithDeadline(bg, time.Now().Add(-time.Second))
		defer cancel2()

		for ctx, want := range map[context.Context]error{canceled: context.Canceled, expired: context.DeadlineExceeded} {
			ch, err := s.Scan(ctx, []string{"10.0.0.1"}, Ports(80))
			if !errors.Is(err, want) || ch != nil {
				t.Errorf("Scan: ch = %v, err = %v, want %v", ch, err, want)
			}
		}
		if d.started() != 0 {
			t.Error("подключения начались при отменённом ctx")
		}
	})
}

func TestScan_InputErrorWinsOverCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	cancel()
	s := newTestScanner(t, &fakeDialer{}, nil)
	if _, err := s.Scan(ctx, nil, Ports(80)); !errors.Is(err, ErrNoTargets) {
		t.Errorf("error = %v, want ErrNoTargets", err)
	}
}

// ---- результаты ----

func TestScan_Results(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{open: func(ap netip.AddrPort) bool {
			return ap.Port() == 80 || (ap.Addr() == addr("10.0.0.2") && ap.Port() == 8001)
		}}
		s := newTestScanner(t, d, nil, WithConcurrency(3))

		ports := Union(Ports(22, 80), Range(8000, 8002))
		results := collect(mustScan(t, s, bg, []string{"10.0.0.1", "10.0.0.2"}, ports))
		if len(results) != 10 {
			t.Fatalf("результатов %d, want 10", len(results))
		}

		got := byAddr(t, results)
		for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
			for _, port := range []uint16{22, 80, 8000, 8001, 8002} {
				k := netip.AddrPortFrom(addr(ip), port).String()
				r, ok := got[k]
				if !ok {
					t.Errorf("нет результата для %s", k)
					continue
				}
				wantOpen := port == 80 || (ip == "10.0.0.2" && port == 8001)
				if r.Host != ip || r.IP != addr(ip) || r.Port != port {
					t.Errorf("%s: Host/IP/Port = %q/%v/%d", k, r.Host, r.IP, r.Port)
				}
				if wantOpen && (r.State != StateOpen || r.Err != nil) {
					t.Errorf("%s: State = %v, Err = %v, want open", k, r.State, r.Err)
				}
				if !wantOpen && (r.State != StateClosed || !errors.Is(r.Err, syscall.ECONNREFUSED)) {
					t.Errorf("%s: State = %v, Err = %v, want closed", k, r.State, r.Err)
				}
			}
		}
	})
}

func TestScan_DuplicatesAreScannedOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil)
		hosts := []string{"10.0.0.1", "10.0.0.1", "::ffff:10.0.0.1"}
		results := collect(mustScan(t, s, bg, hosts, Union(Ports(80, 80), Range(80, 81))))
		if len(results) != 2 || len(byAddr(t, results)) != 2 {
			t.Errorf("результатов %d, want 2: %+v", len(results), results)
		}
		if d.started() != 2 {
			t.Errorf("подключений %d, want 2", d.started())
		}
	})
}

func TestScan_DNS(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fakeResolver{answers: map[string]answer{
			"multi.example": {addrs: []netip.Addr{addr("10.0.0.5"), addr("2001:db8::5")}},
		}}
		d := &fakeDialer{}
		s := newTestScanner(t, d, r)

		results := collect(mustScan(t, s, bg, []string{"multi.example", "bad.example"}, Ports(80, 81)))

		// 1 неразрешённое имя + 2 адреса по 2 порта
		if len(results) != 5 {
			t.Fatalf("результатов %d, want 5: %+v", len(results), results)
		}
		// результат по неразрешённому хосту приходит первым
		f := results[0]
		if f.Host != "bad.example" || f.Port != 0 || f.IP.IsValid() || f.State != StateError || !errors.Is(f.Err, ErrUnresolvable) {
			t.Errorf("первый результат = %+v, want ошибка резолвинга bad.example", f)
		}
		for _, res := range results[1:] {
			if res.Host != "multi.example" || res.Port == 0 {
				t.Errorf("результат %+v: want порт multi.example", res)
			}
		}
		if n := len(byAddr(t, results[1:])); n != 4 {
			t.Errorf("уникальных (адрес, порт) %d, want 4", n)
		}
	})
}

func TestScan_OnlyUnresolvableHosts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, &fakeResolver{})
		results := collect(mustScan(t, s, bg, []string{"a.example", "b.example"}, Range(1, 100)))
		if len(results) != 2 || count(results, StateError) != 2 {
			t.Errorf("results = %+v, want 2 ошибки резолвинга", results)
		}
		if d.started() != 0 {
			t.Error("подключения к неразрешённым хостам")
		}
	})
}

func TestScan_PortsAreSpreadAcrossHosts(t *testing.T) {
	// при concurrency 1 порядок виден: по каждому порту обходим все хосты,
	// чтобы нагрузка не била в один хост
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(1))
		collect(mustScan(t, s, bg, []string{"10.0.0.1", "10.0.0.2"}, Range(1, 2)))
		want := []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.1:2", "10.0.0.2:2"}
		if !equalStrings(d.calls, want) {
			t.Errorf("порядок подключений = %v, want %v", d.calls, want)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScan_DoesNotKeepInput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestScanner(t, &fakeDialer{}, nil)
		hosts := []string{"10.0.0.1", "10.0.0.2"}
		ch := mustScan(t, s, bg, hosts, Range(1, 5))
		hosts[0], hosts[1] = "10.9.9.9", "10.9.9.9" // меняем сразу после Scan
		for _, r := range collect(ch) {
			if r.IP == addr("10.9.9.9") {
				t.Fatal("скан использовал изменённый срез хостов")
			}
		}
	})
}

// ---- конкурентность ----

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

func TestScan_ConnectTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{hang: true}
		s := newTestScanner(t, d, nil, WithConcurrency(2), WithConnectTimeout(500*time.Millisecond))

		start := time.Now()
		results := collect(mustScan(t, s, bg, []string{"10.0.0.1"}, Range(1, 4)))

		if count(results, StateTimeout) != 4 {
			t.Errorf("results = %+v, want 4 timeout", results)
		}
		for _, r := range results {
			if r.Duration != 500*time.Millisecond {
				t.Errorf("Duration = %v, want 500ms", r.Duration)
			}
		}
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Errorf("заняло %v, want 1s (4 проверки по 2 за раз)", elapsed)
		}
	})
}

func TestScan_ConnectionsAreClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{open: func(netip.AddrPort) bool { return true }}
		s := newTestScanner(t, d, nil, WithConcurrency(8))
		results := collect(mustScan(t, s, bg, []string{"10.0.0.1", "10.0.0.2"}, Range(1, 50)))

		if count(results, StateOpen) != 100 || len(d.conns) != 100 {
			t.Fatalf("open = %d, соединений %d, want 100", count(results, StateOpen), len(d.conns))
		}
		for i, c := range d.conns {
			if n := c.closes.Load(); n != 1 {
				t.Errorf("соединение %d закрыто %d раз, want 1", i, n)
			}
		}
	})
}

// ---- медленный читатель ----

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

func TestScan_ReaderGoneThenCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(4))
		ctx, cancel := context.WithCancel(bg)
		ch := mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 1000))

		time.Sleep(time.Second) // читатель молчит, воркеры ждут его
		synctest.Wait()
		cancel()
		synctest.Wait() // все горутины скана должны выйти сами

		// то, что успело попасть в буфер, прочитать можно, дальше канал закрыт
		if n := len(collect(ch)); n > 4 {
			t.Errorf("после отмены осталось %d результатов, want не больше размера буфера (4)", n)
		}
		if started := d.started(); started > 8 {
			t.Errorf("начато %d подключений, want не больше 8", started)
		}
	})
}

// ---- отмена ----

func TestScan_CancelStopsTheScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: 10 * time.Millisecond}
		s := newTestScanner(t, d, nil, WithConcurrency(5))
		ctx, cancel := context.WithCancel(bg)

		start := time.Now()
		ch := mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 10000))
		go func() {
			time.Sleep(35 * time.Millisecond)
			cancel()
		}()
		results := collect(ch)

		// к 35мс завершились 3 партии по 5, четвёртая (5 подключений) в процессе
		if n := count(results, StateClosed); n != 15 {
			t.Errorf("завершённых проверок %d, want 15", n)
		}
		if n := count(results, StateCanceled); n != 5 {
			t.Errorf("прерванных проверок %d, want 5", n)
		}
		for _, r := range results {
			if r.State == StateCanceled && !errors.Is(r.Err, context.Canceled) {
				t.Errorf("Err = %v, want context.Canceled", r.Err)
			}
		}
		// новые подключения после отмены не начинались
		if started := d.started(); started != 20 {
			t.Errorf("начато %d подключений, want 20", started)
		}
		// канал закрылся сразу, начатые операции не ждали своих 10мс
		if elapsed := time.Since(start); elapsed != 35*time.Millisecond {
			t.Errorf("скан завершился через %v, want 35ms", elapsed)
		}
	})
}

func TestScan_DeadlineIsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{hang: true}
		s := newTestScanner(t, d, nil, WithConcurrency(3), WithConnectTimeout(time.Hour))
		ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
		defer cancel()

		results := collect(mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 1000)))

		if count(results, StateCanceled) != 3 || len(results) != 3 {
			t.Errorf("results = %+v, want 3 canceled", results)
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v", ctx.Err())
		}
	})
}

func TestScan_CancelDuringResolving(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fakeResolver{answers: map[string]answer{"slow.example": {block: true}}}
		d := &fakeDialer{}
		s := newTestScanner(t, d, r)
		ctx, cancel := context.WithCancel(bg)

		start := time.Now()
		ch := mustScan(t, s, ctx, []string{"slow.example", "10.0.0.1"}, Range(1, 100))
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()
		results := collect(ch)

		if len(results) != 0 {
			t.Errorf("results = %+v, want ничего", results)
		}
		if d.started() != 0 {
			t.Error("подключения начались до конца резолвинга")
		}
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Errorf("канал закрылся через %v, want 1s", elapsed)
		}
	})
}

func TestScan_CancelWhileDeliveringResolveFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// неразрешённых имён больше, чем влезает в буфер, а читателя нет
		var hosts []string
		for i := range 30 {
			hosts = append(hosts, "n"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
		}
		s := newTestScanner(t, &fakeDialer{}, &fakeResolver{}, WithConcurrency(2)) // буфер 2
		ctx, cancel := context.WithCancel(bg)
		ch := mustScan(t, s, ctx, hosts, Ports(80))

		time.Sleep(time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()

		if n := len(collect(ch)); n > 2 {
			t.Errorf("после отмены осталось %d результатов, want не больше буфера (2)", n)
		}
	})
}

// ---- повторное использование ----

func TestScan_ScannerCanBeReused(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{open: func(ap netip.AddrPort) bool { return ap.Port() == 80 }}
		s := newTestScanner(t, d, nil, WithConcurrency(4))

		for i, hosts := range [][]string{{"10.0.0.1"}, {"10.0.0.2", "10.0.0.3"}, {"10.0.0.1"}} {
			results := collect(mustScan(t, s, bg, hosts, Ports(80, 81)))
			if want := len(hosts) * 2; len(results) != want || count(results, StateOpen) != len(hosts) {
				t.Errorf("запуск %d: results = %+v", i, results)
			}
		}
		if len(s.sem) != 0 {
			t.Errorf("после сканов занято слотов: %d", len(s.sem))
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

// ---- масштаб ----

func TestScan_ManyHostsAndAllPorts(t *testing.T) {
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

// ---- реальная сеть, localhost ----

func TestScan_RealLocalhost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	openPort := ln.Addr().(*net.TCPAddr).Port

	// сервер принимает подключения и ждёт, пока клиент их закроет
	closedByClient := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			closedByClient <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		closedByClient <- err
	}()

	// закрытый порт: заняли и освободили
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	s, err := New(WithConnectTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(mustScan(t, s, bg, []string{"127.0.0.1"}, Ports(openPort, closedPort)))

	if len(results) != 2 {
		t.Fatalf("results = %+v, want 2", results)
	}
	for _, r := range results {
		switch int(r.Port) {
		case openPort:
			if r.State != StateOpen || r.Err != nil || r.Duration <= 0 {
				t.Errorf("открытый порт: %+v", r)
			}
		case closedPort:
			if r.State != StateClosed || r.Err == nil {
				t.Errorf("закрытый порт: %+v", r)
			}
		default:
			t.Errorf("лишний результат %+v", r)
		}
	}
	if err := <-closedByClient; !errors.Is(err, io.EOF) {
		t.Errorf("сервер увидел %v, want io.EOF: скан не закрыл соединение", err)
	}
}

// ---- produce и check по отдельности ----

func TestProduce_JobsInOrder(t *testing.T) {
	jobs := make(chan job)
	go func() {
		defer close(jobs)
		produce(bg, []endpoint{{"a", addr("10.0.0.1")}, {"b", addr("10.0.0.2")}}, Range(1, 2), jobs)
	}()
	var got []string
	for j := range jobs {
		got = append(got, netip.AddrPortFrom(j.ep.ip, j.port).String())
	}
	want := []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.1:2", "10.0.0.2:2"}
	if !equalStrings(got, want) {
		t.Errorf("задачи = %v, want %v", got, want)
	}
}

func TestProduce_NothingIsSentAfterCancel(t *testing.T) {
	// читатель уже ждёт задачу: без проверки ctx между задачами select
	// с равными шансами отдал бы часть задач и после отмены
	synctest.Test(t, func(t *testing.T) {
		for range 50 {
			jobs := make(chan job)
			received := make(chan int)
			go func() {
				n := 0
				for range jobs {
					n++
				}
				received <- n
			}()
			synctest.Wait() // читатель точно встал в ожидание

			produce(canceledCtx(), []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 1000), jobs)
			close(jobs)
			if n := <-received; n != 0 {
				t.Fatalf("после отмены отправлено %d задач, want 0", n)
			}
		}
	})
}

func TestProduce_StopsWhenCanceledInTheMiddle(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	jobs := make(chan job)
	done := make(chan struct{})
	received := 0
	go func() {
		defer close(done)
		for range jobs {
			received++
			if received == 3 {
				cancel()
			}
		}
	}()
	produce(ctx, []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 1000), jobs)
	close(jobs)
	<-done
	// четвёртая могла уйти, пока cancel ещё не выполнился, пятая - уже нет
	if received < 3 || received > 4 {
		t.Errorf("отправлено %d задач, want 3 или 4", received)
	}
}

func TestProduce_ReturnsWhenNobodyTakesJobs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		done := make(chan struct{})
		go func() {
			defer close(done)
			produce(ctx, []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 10), make(chan job)) // читателя нет
		}()
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("produce вернулась без отмены")
		default:
		}
		cancel()
		<-done
	})
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

func TestCheck_CanceledBeforeStart(t *testing.T) {
	d := &fakeDialer{}
	s := newTestScanner(t, d, nil)
	// слот свободен и ctx отменён: select без проверки выбирал бы ветку
	// случайно, поэтому повторяем
	for range 50 {
		if _, ok := s.check(canceledCtx(), job{ep: endpoint{"a", addr("10.0.0.1")}, port: 80}); ok {
			t.Fatal("check при отменённом ctx вернула результат")
		}
	}
	if d.started() != 0 {
		t.Error("подключение началось при отменённом ctx")
	}
	if n := len(s.sem); n != 0 {
		t.Errorf("занято слотов %d, want 0", n)
	}
}

func TestCheck_CanceledWhileWaitingForSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(2))
		s.sem <- struct{}{} // оба слота заняты кем-то другим
		s.sem <- struct{}{}

		ctx, cancel := context.WithCancel(bg)
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		_, ok := s.check(ctx, job{ep: endpoint{"a", addr("10.0.0.1")}, port: 80})

		if ok {
			t.Error("check вернула результат, хотя слот так и не освободился")
		}
		if elapsed := time.Since(start); elapsed != 10*time.Millisecond {
			t.Errorf("check вернулась через %v, want 10ms", elapsed)
		}
		if d.started() != 0 {
			t.Error("подключение началось без слота")
		}
		if n := len(s.sem); n != 2 {
			t.Errorf("слотов занято %d, want 2: чужие слоты не должны освобождаться", n)
		}
	})
}

func TestScan_CancelWhileWaitingForSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Scan A держит оба слота зависшими подключениями, Scan B ждёт слот
		d := &fakeDialer{}
		hang := dialFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
			if ap, _ := netip.ParseAddrPort(a); ap.Addr() == addr("10.0.0.1") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return d.DialContext(ctx, n, a)
		})
		s := newTestScanner(t, hang, nil, WithConcurrency(2), WithConnectTimeout(time.Hour))

		ctxA, cancelA := context.WithCancel(bg)
		chA := mustScan(t, s, ctxA, []string{"10.0.0.1"}, Range(1, 10))
		time.Sleep(time.Second)
		synctest.Wait()

		ctxB, cancelB := context.WithCancel(bg)
		chB := mustScan(t, s, ctxB, []string{"10.0.0.2"}, Range(1, 10))
		time.Sleep(time.Second)
		synctest.Wait()
		cancelB()

		if got := collect(chB); len(got) != 0 {
			t.Errorf("B: results = %+v, want ничего: слотов не было", got)
		}
		if d.started() != 0 {
			t.Error("B начал подключения, хотя слотов не было")
		}

		cancelA()
		collect(chA)
		if n := len(s.sem); n != 0 {
			t.Errorf("после обоих сканов занято слотов %d, want 0", n)
		}
	})
}

// ---- DNS внутри Scan ----

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
