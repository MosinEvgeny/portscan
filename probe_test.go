package portscan

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestProbe_Open(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := &fakeConn{}
		var network, address string
		d := dialFunc(func(_ context.Context, n, a string) (net.Conn, error) {
			network, address = n, a
			time.Sleep(7 * time.Millisecond)
			return conn, nil
		})

		ep := endpoint{host: "example.com", ip: addr("93.184.216.34")}
		got := probe(context.Background(), d, ep, 443, time.Second)

		want := Result{Host: "example.com", IP: addr("93.184.216.34"), Port: 443, State: StateOpen, Duration: 7 * time.Millisecond}
		if got != want {
			t.Errorf("probe = %+v, want %+v", got, want)
		}
		if network != "tcp" || address != "93.184.216.34:443" {
			t.Errorf("dial(%q, %q), want tcp 93.184.216.34:443", network, address)
		}
		if n := conn.closes.Load(); n != 1 {
			t.Errorf("соединение закрыто %d раз, want 1", n)
		}
	})
}

func TestProbe_AddressFormat(t *testing.T) {
	tests := []struct {
		ip   string
		port uint16
		want string
	}{
		{"192.168.1.10", 80, "192.168.1.10:80"},
		{"::1", 22, "[::1]:22"},
		{"2001:db8::1", 65535, "[2001:db8::1]:65535"},
		{"fe80::1%en0", 8080, "[fe80::1%en0]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			var got string
			d := dialFunc(func(_ context.Context, _, address string) (net.Conn, error) {
				got = address
				return nil, syscall.ECONNREFUSED
			})
			probe(context.Background(), d, endpoint{host: "h", ip: addr(tt.ip)}, tt.port, time.Second)
			if got != tt.want {
				t.Errorf("адрес = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProbe_ErrorsAreClassifiedAndKept(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want State
	}{
		{"отказ", dialErr(syscall.ECONNREFUSED), StateClosed},
		{"сеть недоступна", dialErr(syscall.ENETUNREACH), StateUnreachable},
		{"хост недоступен", dialErr(syscall.EHOSTUNREACH), StateUnreachable},
		{"прочее", dialErr(syscall.EMFILE), StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := dialFunc(func(context.Context, string, string) (net.Conn, error) { return nil, tt.err })
			got := probe(context.Background(), d, endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)
			if got.State != tt.want {
				t.Errorf("State = %v, want %v", got.State, tt.want)
			}
			if !errors.Is(got.Err, tt.err) {
				t.Errorf("Err = %v, want %v", got.Err, tt.err)
			}
		})
	}
}

func TestProbe_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		got := probe(context.Background(), hangingDialer(), endpoint{host: "h", ip: addr("10.0.0.1")}, 80, 500*time.Millisecond)

		if got.State != StateTimeout {
			t.Errorf("State = %v, want timeout", got.State)
		}
		if got.Duration != 500*time.Millisecond {
			t.Errorf("Duration = %v, want 500ms", got.Duration)
		}
		if !errors.Is(got.Err, context.DeadlineExceeded) {
			t.Errorf("Err = %v, want DeadlineExceeded", got.Err)
		}
	})
}

func TestProbe_TimeoutInNetShape(t *testing.T) {
	// как отдаёт net.Dialer, когда подключение не завершилось: это не context.DeadlineExceeded
	synctest.Test(t, func(t *testing.T) {
		d := dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}
		})
		got := probe(context.Background(), d, endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)
		if got.State != StateTimeout {
			t.Errorf("State = %v, want timeout", got.State)
		}
	})
}

func TestProbe_ScanCanceledWhileDialing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(100 * time.Millisecond)
			cancel()
		}()

		got := probe(ctx, hangingDialer(), endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)

		if got.State != StateCanceled {
			t.Errorf("State = %v, want canceled", got.State)
		}
		if got.Duration != 100*time.Millisecond {
			t.Errorf("Duration = %v, want 100ms", got.Duration)
		}
		if !errors.Is(got.Err, context.Canceled) {
			t.Errorf("Err = %v, want Canceled", got.Err)
		}
	})
}

func TestProbe_ScanDeadlineIsCancellationNotTimeout(t *testing.T) {
	// дедлайн всего скана короче таймаута подключения: это отмена, а не timeout
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		got := probe(ctx, hangingDialer(), endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)

		if got.State != StateCanceled {
			t.Errorf("State = %v, want canceled", got.State)
		}
		if got.Duration != 100*time.Millisecond {
			t.Errorf("Duration = %v, want 100ms", got.Duration)
		}
	})
}

func TestProbe_AttemptContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var attempt context.Context
		d := dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			attempt = ctx
			return nil, syscall.ECONNREFUSED
		})

		start := time.Now()
		probe(context.Background(), d, endpoint{host: "h", ip: addr("10.0.0.1")}, 80, 2*time.Second)

		deadline, ok := attempt.Deadline()
		if !ok || deadline.Sub(start) != 2*time.Second {
			t.Errorf("дедлайн попытки = %v (задан: %v), want start+2s", deadline.Sub(start), ok)
		}
		// после probe контекст попытки освобождён, таймер не висит
		if attempt.Err() == nil {
			t.Error("контекст попытки не отменён после probe")
		}
	})
}

func TestProbe_ConnectionIsClosedEvenIfDialerReturnsError(t *testing.T) {
	conn := &fakeConn{}
	d := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		return conn, errors.New("boom")
	})
	got := probe(context.Background(), d, endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)
	if got.State != StateError {
		t.Errorf("State = %v, want error", got.State)
	}
	if n := conn.closes.Load(); n != 1 {
		t.Errorf("соединение закрыто %d раз, want 1", n)
	}
}

func TestProbe_ConnectionOpenedJustBeforeCancel(t *testing.T) {
	// соединение открылось, а скан отменили: порт всё равно открыт, соединение закрыто
	conn := &fakeConn{}
	ctx, cancel := context.WithCancel(context.Background())
	d := dialFunc(func(context.Context, string, string) (net.Conn, error) {
		cancel()
		return conn, nil
	})
	got := probe(ctx, d, endpoint{host: "h", ip: addr("10.0.0.1")}, 80, time.Second)
	if got.State != StateOpen || got.Err != nil {
		t.Errorf("State = %v, Err = %v, want open", got.State, got.Err)
	}
	if n := conn.closes.Load(); n != 1 {
		t.Errorf("соединение закрыто %d раз, want 1", n)
	}
}

// ниже - настоящая сеть, localhost

func TestProbe_RealOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	// сервер ждёт, когда клиент закроет соединение
	serverSaw := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverSaw <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		serverSaw <- err
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	got := probe(context.Background(), &net.Dialer{}, endpoint{host: "localhost", ip: addr("127.0.0.1")}, port, 5*time.Second)

	if got.State != StateOpen || got.Err != nil {
		t.Fatalf("State = %v, Err = %v, want open", got.State, got.Err)
	}
	if got.Duration < 0 {
		t.Errorf("Duration = %v, want >= 0", got.Duration)
	}
	if err := <-serverSaw; !errors.Is(err, io.EOF) {
		t.Errorf("сервер увидел %v, want io.EOF: probe не закрыл соединение", err)
	}
}

func TestProbe_RealClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()

	got := probe(context.Background(), &net.Dialer{}, endpoint{host: "localhost", ip: addr("127.0.0.1")}, port, 10*time.Second)
	if got.State != StateClosed {
		t.Errorf("State = %v (%v), want closed", got.State, got.Err)
	}
	if !errors.Is(got.Err, syscall.ECONNREFUSED) && !errors.Is(got.Err, wsaConnRefused) {
		t.Errorf("Err = %v, want отказ в подключении", got.Err)
	}
}

func TestProbe_RealCanceledScan(t *testing.T) {
	ctx := canceledCtx()
	got := probe(ctx, &net.Dialer{}, endpoint{host: "localhost", ip: addr("127.0.0.1")}, 9, time.Second)
	if got.State != StateCanceled {
		t.Errorf("State = %v (%v), want canceled", got.State, got.Err)
	}
}
