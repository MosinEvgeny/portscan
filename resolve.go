package portscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Resolver переводит имя хоста в IP-адреса. Подходит *net.Resolver.
// Scanner вызывает его из многих горутин сразу, поэтому реализация должна быть к этому готова
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var _ Resolver = (*net.Resolver)(nil)

// timeoutResolver ограничивает время одного DNS-запроса.
type timeoutResolver struct {
	r       Resolver
	timeout time.Duration
}

func (t timeoutResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	return t.r.LookupNetIP(ctx, network, host)
}

// endpoint - адрес, который будем сканировать
type endpoint struct {
	host string
	ip   netip.Addr
}

type lookup struct {
	addrs []netip.Addr
	err   error
	took  time.Duration
}

// resolve превращает хосты в адреса для сканирования.
//
// Хост, который не разрешился, остальных не останавливает: по нему
// возвращается Result с ошибкой. Если несколько хостов дали один IP, он
// остаётся за тем, кто был в списке раньше. Порядок результатов совпадает
// с порядком хостов. Сама resolve падает только при отмене ctx.
func resolve(ctx context.Context, r Resolver, targets []target, parallelism int) ([]endpoint, []Result, error) {
	lookups := make([]lookup, len(targets))
	var names []int // индексы хостов, которым нужен DNS
	for i, t := range targets {
		if !t.addr.IsValid() {
			names = append(names, i)
		}
	}
	if err := lookupAll(ctx, r, targets, lookups, names, parallelism); err != nil {
		return nil, nil, err
	}

	var (
		endpoints []endpoint
		failed    []Result
		seen      = make(map[netip.Addr]struct{})
	)
	for i, t := range targets {
		addrs := []netip.Addr{t.addr}
		if !t.addr.IsValid() {
			l := lookups[i]
			if l.err != nil {
				failed = append(failed, Result{Host: t.host, State: StateError, Duration: l.took, Err: l.err})
				continue
			}
			addrs = l.addrs
		}
		for _, ip := range addrs {
			if _, dup := seen[ip]; dup {
				continue
			}
			seen[ip] = struct{}{}
			endpoints = append(endpoints, endpoint{host: t.host, ip: ip})
		}
	}
	return endpoints, failed, nil
}

// lookupAll разрешает targets[i] для i из idx, не больше parallelism за раз,
// и кладёт ответ в out[i]. Возвращает ошибку только при отмене ctx.
func lookupAll(ctx context.Context, r Resolver, targets []target, out []lookup, idx []int, parallelism int) error {
	if len(idx) == 0 {
		return ctx.Err()
	}
	workers := max(1, min(parallelism, len(idx)))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := range jobs {
				start := time.Now()
				addrs, err := lookupName(ctx, r, targets[i].host)
				out[i] = lookup{addrs: addrs, err: err, took: time.Since(start)}
			}
		})
	}
send:
	for _, i := range idx {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	wg.Wait()
	return ctx.Err()
}

// lookupName возвращает адреса имени, IPv4 раньше IPv6 (для стабильного порядка).
// Пустой ответ считается ошибкой. Дубли убирает resolve.
func lookupName(ctx context.Context, r Resolver, name string) ([]netip.Addr, error) {
	got, err := r.LookupNetIP(ctx, "ip", name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnresolvable, err)
	}
	// копия: срез, который вернул resolver, не трогаем
	addrs := make([]netip.Addr, 0, len(got))
	for _, a := range got {
		if a.IsValid() {
			addrs = append(addrs, a.Unmap())
		}
	}
	slices.SortFunc(addrs, netip.Addr.Compare)
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: no addresses for %q", ErrUnresolvable, name)
	}
	return addrs, nil
}
