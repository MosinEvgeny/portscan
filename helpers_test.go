package portscan

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Общие заглушки и помощники для тестов пакета.

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustTargets(t *testing.T, hosts ...string) []target {
	t.Helper()
	targets, err := parseTargets(hosts)
	if err != nil {
		t.Fatalf("parseTargets(%q): %v", hosts, err)
	}
	return targets
}

func hostsOf(targets []target) []string {
	var hosts []string
	for _, t := range targets {
		hosts = append(hosts, t.host)
	}
	return hosts
}

var bg = context.Background()

func canceledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func expiredCtx() context.Context {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	cancel()
	return ctx
}

// dialErr - ошибка в том виде, в каком её отдаёт net.Dialer:
// "dial tcp 1.2.3.4:80: connect: connection refused"
func dialErr(errno error) error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", errno)}
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

// fakeNetError - свой net.Error с заданным Timeout
type fakeNetError struct{ timeout bool }

func (e fakeNetError) Error() string   { return "fake net error" }
func (e fakeNetError) Timeout() bool   { return e.timeout }
func (e fakeNetError) Temporary() bool { return false }

// fakeConn считает вызовы Close, остальные методы net.Conn не нужны
type fakeConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *fakeConn) Close() error {
	c.closes.Add(1)
	return nil
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// dialer, который висит, пока не истечёт контекст попытки
func hangingDialer() Dialer {
	return dialFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
}

// что fakeResolver отвечает на конкретное имя
type answer struct {
	addrs []netip.Addr
	err   error
	delay time.Duration // сколько resolver "думает"
	block bool          // висит, пока не отменят ctx
}

// fakeResolver отвечает по таблице. Имя, которого в таблице нет, - "no such host".
type fakeResolver struct {
	answers map[string]answer

	mu          sync.Mutex
	calls       []string // имена в порядке вызова
	networks    []string
	done        []string // имена в порядке завершения
	inFlight    int
	maxInFlight int
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	f.calls = append(f.calls, host)
	f.networks = append(f.networks, network)
	f.inFlight++
	f.maxInFlight = max(f.maxInFlight, f.inFlight)
	a, known := f.answers[host]
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.inFlight--
		f.done = append(f.done, host)
		f.mu.Unlock()
	}()

	if a.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if a.delay > 0 {
		select {
		case <-time.After(a.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !known {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return a.addrs, a.err
}

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
