package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

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
		if !slices.Equal(d.calls, want) {
			t.Errorf("порядок подключений = %v, want %v", d.calls, want)
		}
	})
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
	if !slices.Equal(got, want) {
		t.Errorf("задачи = %v, want %v", got, want)
	}
}

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
