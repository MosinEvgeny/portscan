package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// На Windows ошибки сети приходят как syscall.Errno с кодами WSA*, и они не
// равны syscall.ECONNREFUSED и остальным (там свои выдуманные значения),
// поэтому перечислены отдельно. На других ОС таких errno нет, сравнение
// просто не сработает.
const (
	wsaNetDown     = syscall.Errno(10050)
	wsaNetUnreach  = syscall.Errno(10051)
	wsaTimedOut    = syscall.Errno(10060)
	wsaConnRefused = syscall.Errno(10061)
	wsaHostUnreach = syscall.Errno(10065)
)

// classify определяет состояние порта по результату подключения.
//
// ctx - контекст всего скана, а не одной попытки: по нему отличаем отмену от
// таймаута подключения. Текст ошибок не разбирается, только errors.Is и errors.As.
//
// Если ответ уже пришёл (отказ или недоступность), отмена после него ничего
// не меняет. Всё остальное после отмены ctx считается отменой.
func classify(ctx context.Context, err error) State {
	switch {
	case err == nil:
		return StateOpen
	case isRefused(err):
		return StateClosed
	case isUnreachable(err):
		return StateUnreachable
	case ctx.Err() != nil || errors.Is(err, context.Canceled):
		return StateCanceled
	case isTimeout(err):
		return StateTimeout
	}
	return StateError
}

func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaConnRefused)
}

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EHOSTDOWN) ||
		errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, wsaNetUnreach) ||
		errors.Is(err, wsaHostUnreach) ||
		errors.Is(err, wsaNetDown)
}

func isTimeout(err error) bool {
	if errors.Is(err, wsaTimedOut) {
		return true
	}
	// i/o timeout из net, context.DeadlineExceeded и ETIMEDOUT - всё это
	// net.Error с Timeout() == true. WSAETIMEDOUT - нет, поэтому проверен выше.
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
