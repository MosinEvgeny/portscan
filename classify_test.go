package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	t.Parallel()
	alive := context.Background()

	tests := []struct {
		name string
		ctx  context.Context // контекст всего скана
		err  error
		want State
	}{
		{"нет ошибки", alive, nil, StateOpen},

		// closed
		{"отказ, как отдаёт Linux и macOS", alive, dialErr(syscall.ECONNREFUSED), StateClosed},
		{"отказ, WSAECONNREFUSED на Windows", alive, dialErr(wsaConnRefused), StateClosed},
		{"отказ без обёрток", alive, syscall.ECONNREFUSED, StateClosed},
		{"отказ под %w", alive, fmt.Errorf("probe: %w", dialErr(syscall.ECONNREFUSED)), StateClosed},
		{"отказ, текст ошибки не важен", alive, fmt.Errorf("абракадабра: %w", syscall.ECONNREFUSED), StateClosed},
		{"отказ внутри errors.Join", alive, errors.Join(errors.New("другая"), dialErr(syscall.ECONNREFUSED)), StateClosed},

		// unreachable
		{"сеть недоступна", alive, dialErr(syscall.ENETUNREACH), StateUnreachable},
		{"хост недоступен", alive, dialErr(syscall.EHOSTUNREACH), StateUnreachable},
		{"сеть лежит", alive, dialErr(syscall.ENETDOWN), StateUnreachable},
		{"WSAENETUNREACH", alive, dialErr(wsaNetUnreach), StateUnreachable},
		{"WSAEHOSTUNREACH", alive, dialErr(wsaHostUnreach), StateUnreachable},
		{"WSAENETDOWN", alive, dialErr(wsaNetDown), StateUnreachable},

		// timeout
		{"i/o timeout из net", alive, &net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded}, StateTimeout},
		{"context.DeadlineExceeded", alive, context.DeadlineExceeded, StateTimeout},
		{"DeadlineExceeded под %w", alive, fmt.Errorf("x: %w", context.DeadlineExceeded), StateTimeout},
		{"ETIMEDOUT от ОС", alive, dialErr(syscall.ETIMEDOUT), StateTimeout},
		{"WSAETIMEDOUT", alive, dialErr(wsaTimedOut), StateTimeout},
		{"свой net.Error с Timeout()", alive, fakeNetError{timeout: true}, StateTimeout},

		// canceled
		{"context.Canceled", alive, context.Canceled, StateCanceled},
		{"Canceled внутри OpError", alive, &net.OpError{Op: "dial", Err: context.Canceled}, StateCanceled},

		// отмена всего скана
		{"контекст отменён, ошибка отмены", canceledCtx(), &net.OpError{Op: "dial", Err: context.Canceled}, StateCanceled},
		{"контекст отменён, ошибка таймаута", canceledCtx(), &net.OpError{Err: os.ErrDeadlineExceeded}, StateCanceled},
		{"контекст отменён, неизвестная ошибка", canceledCtx(), errors.New("boom"), StateCanceled},
		{"дедлайн скана истёк, ошибка таймаута", expiredCtx(), &net.OpError{Err: os.ErrDeadlineExceeded}, StateCanceled},
		{"ответ пришёл до отмены: отказ", canceledCtx(), dialErr(syscall.ECONNREFUSED), StateClosed},
		{"ответ пришёл до отмены: недоступно", canceledCtx(), dialErr(syscall.ENETUNREACH), StateUnreachable},
		{"соединение успело открыться", canceledCtx(), nil, StateOpen},

		// error
		{"неизвестная ошибка", alive, errors.New("boom"), StateError},
		{"нет свободных дескрипторов", alive, dialErr(syscall.EMFILE), StateError},
		{"нет прав", alive, dialErr(syscall.EACCES), StateError},
		{"сброс соединения", alive, dialErr(syscall.ECONNRESET), StateError},
		{"нет локального адреса", alive, dialErr(syscall.EADDRNOTAVAIL), StateError},
		{"семейство адресов не поддерживается", alive, dialErr(syscall.EAFNOSUPPORT), StateError},
		{"net.Error без таймаута", alive, fakeNetError{timeout: false}, StateError},

		// текст не разбирается: даже точные фразы из net не работают без настоящей ошибки
		{"текст про отказ", alive, errors.New("connect: connection refused"), StateError},
		{"текст про таймаут", alive, errors.New("dial tcp 1.2.3.4:80: i/o timeout"), StateError},
		{"текст про отмену", alive, errors.New("operation was canceled"), StateError},
		{"текст про маршрут", alive, errors.New("connect: no route to host"), StateError},
		{"текст про сеть", alive, errors.New("connect: network is unreachable"), StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := classify(tt.ctx, tt.err); got != tt.want {
				t.Errorf("classify(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// настоящие ошибки от net.Dialer, без подделок
func TestClassify_RealDialErrors(t *testing.T) {
	d := &net.Dialer{}

	t.Run("порт закрыт", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close() // на порту больше никто не слушает

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = d.DialContext(ctx, "tcp", addr)
		if got := classify(context.Background(), err); got != StateClosed {
			t.Errorf("classify(%v) = %v, want closed", err, got)
		}
	})

	t.Run("контекст уже отменён", func(t *testing.T) {
		ctx := canceledCtx()
		_, err := d.DialContext(ctx, "tcp", "127.0.0.1:9")
		if got := classify(ctx, err); got != StateCanceled {
			t.Errorf("classify(%v) = %v, want canceled", err, got)
		}
		// и без контекста скана одной ошибки хватает
		if got := classify(context.Background(), err); got != StateCanceled {
			t.Errorf("classify(%v) = %v, want canceled", err, got)
		}
	})

	t.Run("таймаут попытки", func(t *testing.T) {
		attempt, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		_, err := d.DialContext(attempt, "tcp", "127.0.0.1:9")
		// скан не отменён, истекла только попытка
		if got := classify(context.Background(), err); got != StateTimeout {
			t.Errorf("classify(%v) = %v, want timeout", err, got)
		}
	})
}
