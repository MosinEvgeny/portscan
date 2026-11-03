package portscan

import (
	"fmt"
	"time"
)

const (
	defaultConcurrency = 100
	defaultTimeout     = time.Second

	maxResolveWorkers = 16  // сколько DNS-запросов идёт одновременно, не больше
	maxResultBuffer   = 256 // размер буфера канала с результатами, не больше
)

// Option настраивает Scanner в New.
type Option func(*config) error

type config struct {
	concurrency int
	timeout     time.Duration
	resolver    Resolver
	dialer      Dialer
}

// WithConcurrency задаёт, сколько подключений может идти одновременно
// (по умолчанию 100). Лимит общий для всех Scan одного Scanner.
//
// Каждое подключение занимает файловый дескриптор, а на macOS лимит
// по умолчанию всего 256 (ulimit -n), так что с большими значениями
// можно упереться в него.
func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("%w: concurrency must be at least 1, got %d", ErrInvalidOption, n)
		}
		c.concurrency = n
		return nil
	}
}

// WithConnectTimeout задаёт, сколько ждать подключения к одному порту
// (по умолчанию секунда).
func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("%w: connect timeout must be positive, got %v", ErrInvalidOption, d)
		}
		c.timeout = d
		return nil
	}
}

// WithResolver подменяет DNS-резолвер (по умолчанию net.Resolver).
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		if r == nil {
			return fmt.Errorf("%w: resolver is nil", ErrInvalidOption)
		}
		c.resolver = r
		return nil
	}
}

// WithDialer подменяет способ подключения (по умолчанию net.Dialer).
// Таймаут задавать в нём не нужно: он приходит через контекст.
func WithDialer(d Dialer) Option {
	return func(c *config) error {
		if d == nil {
			return fmt.Errorf("%w: dialer is nil", ErrInvalidOption)
		}
		c.dialer = d
		return nil
	}
}
