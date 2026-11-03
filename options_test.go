package portscan

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	s, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.concurrency != 100 {
		t.Errorf("concurrency = %d, want 100", s.cfg.concurrency)
	}
	if s.cfg.timeout != time.Second {
		t.Errorf("timeout = %v, want 1s", s.cfg.timeout)
	}
	if s.cfg.resolver == nil || s.cfg.dialer == nil {
		t.Error("resolver и dialer по умолчанию должны быть заданы")
	}
	if cap(s.sem) != 100 {
		t.Errorf("слотов на подключения %d, want 100", cap(s.sem))
	}
}

func TestNew_Options(t *testing.T) {
	r, d := &fakeResolver{}, &fakeDialer{}
	s, err := New(
		WithConcurrency(7),
		WithConnectTimeout(250*time.Millisecond),
		WithResolver(r),
		WithDialer(d),
	)
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.concurrency != 7 || cap(s.sem) != 7 {
		t.Errorf("concurrency = %d, слотов %d, want 7", s.cfg.concurrency, cap(s.sem))
	}
	if s.cfg.timeout != 250*time.Millisecond {
		t.Errorf("timeout = %v", s.cfg.timeout)
	}
	if s.cfg.resolver != Resolver(r) || s.cfg.dialer != Dialer(d) {
		t.Error("resolver или dialer не подменились")
	}
}

func TestNew_LastOptionWins(t *testing.T) {
	s, err := New(WithConcurrency(5), WithConcurrency(9))
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.concurrency != 9 {
		t.Errorf("concurrency = %d, want 9", s.cfg.concurrency)
	}
}

func TestNew_NilOptionIsIgnored(t *testing.T) {
	if _, err := New(nil, WithConcurrency(3), nil); err != nil {
		t.Errorf("New(nil, ...) error = %v", err)
	}
}

func TestNew_InvalidOptions(t *testing.T) {
	var nilResolver Resolver
	var nilDialer Dialer
	tests := []struct {
		name string
		opt  Option
	}{
		{"concurrency 0", WithConcurrency(0)},
		{"concurrency отрицательный", WithConcurrency(-5)},
		{"timeout 0", WithConnectTimeout(0)},
		{"timeout отрицательный", WithConnectTimeout(-time.Second)},
		{"nil resolver", WithResolver(nilResolver)},
		{"nil dialer", WithDialer(nilDialer)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(tt.opt)
			if !errors.Is(err, ErrInvalidOption) {
				t.Errorf("error = %v, want ErrInvalidOption", err)
			}
			if s != nil {
				t.Error("вместе с ошибкой вернулся Scanner")
			}
		})
	}
}

func TestNew_AllProblemsAreReported(t *testing.T) {
	_, err := New(WithConcurrency(0), WithConnectTimeout(-time.Second), WithDialer(nil))
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("error = %v, want ErrInvalidOption", err)
	}
	for _, want := range []string{"concurrency", "timeout", "dialer"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestNew_ScannersAreIndependent(t *testing.T) {
	a, _ := New(WithConcurrency(2))
	b, _ := New(WithConcurrency(50))
	if a.cfg.concurrency != 2 || b.cfg.concurrency != 50 {
		t.Error("настройки одного Scanner влияют на другой")
	}
	if a.sem == b.sem {
		t.Error("у разных Scanner общие слоты")
	}
}

func TestNew_DefaultsUseStandardTypes(t *testing.T) {
	s, _ := New()
	if _, ok := s.cfg.resolver.(*net.Resolver); !ok {
		t.Errorf("resolver по умолчанию %T, want *net.Resolver", s.cfg.resolver)
	}
	d, ok := s.cfg.dialer.(*net.Dialer)
	if !ok {
		t.Fatalf("dialer по умолчанию %T, want *net.Dialer", s.cfg.dialer)
	}
	if d.Timeout != 0 {
		t.Errorf("у dialer задан свой Timeout %v: таймаут должен приходить через контекст", d.Timeout)
	}
	// соединение закрывается сразу, keep-alive ему ни к чему
	if d.KeepAlive >= 0 {
		t.Errorf("KeepAlive = %v, want отключён (отрицательный)", d.KeepAlive)
	}
}
