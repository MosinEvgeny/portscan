package portscan

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Dialer открывает TCP-соединение. Подходит *net.Dialer.
// Scanner вызывает его из многих горутин сразу, поэтому реализация должна быть к этому готова
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var _ Dialer = (*net.Dialer)(nil)

// probe проверяет один порт. ctx - контекст всего скана, timeout - на одну
// попытку подключения. Открывшееся соединение закрывается сразу: нужен только
// сам факт подключения.
func probe(ctx context.Context, d Dialer, ep endpoint, port uint16, timeout time.Duration) Result {
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := netip.AddrPortFrom(ep.ip, port).String()
	start := time.Now()
	conn, err := d.DialContext(attempt, "tcp", addr)
	took := time.Since(start)

	if conn != nil {
		_ = conn.Close() // ошибка закрытия ничего не говорит о порте
	}
	return Result{
		Host:     ep.host,
		IP:       ep.ip,
		Port:     port,
		State:    classify(ctx, err),
		Duration: took,
		Err:      err,
	}
}
