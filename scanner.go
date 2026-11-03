package portscan

import (
	"context"
	"net"
	"sync"
)

// Scanner проверяет TCP-порты. Создаётся через New, дальше не меняется и
// безопасен для одновременного использования из нескольких горутин.
type Scanner struct {
	cfg config
	sem chan struct{} // слоты на подключения, общие для всех Scan
}

// New создаёт Scanner. Если неверны сразу несколько опций, в ошибке будут все.
func New(opts ...Option) (*Scanner, error) {
	cfg := config{
		concurrency: defaultConcurrency,
		timeout:     defaultTimeout,
		resolver:    new(net.Resolver),
		dialer:      &net.Dialer{KeepAlive: -1}, // соединение сразу закрывается, keep-alive не нужен
	}
	var errs []error
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			errs = append(errs, err)
		}
	}
	if err := joinErrors(errs); err != nil {
		return nil, err
	}
	return &Scanner{cfg: cfg, sem: make(chan struct{}, cfg.concurrency)}, nil
}

// Scan проверяет порты ports на хостах hosts и возвращает канал с результатами.
//
// Ошибка возвращается, только если скан не удалось начать: список хостов или
// портов пуст или некорректен, либо ctx уже отменён. Всё остальное приходит
// в канале. Сначала идут результаты по неразрешённым хостам (см. Result),
// потом по портам. Каждая пара (IP, порт) проверяется один раз, порядок
// результатов не гарантируется.
//
// Канал закрывается, когда проверки закончились или остановлены отменой ctx:
// новые не начинаются, начатые прерываются и приходят как StateCanceled.
// Результат, который некому принять, после отмены отбрасывается. Если после
// закрытия канала ctx.Err() != nil, результаты неполные.
//
// Канал нужно дочитать до конца или отменить ctx, иначе горутины скана
// останутся ждать читателя. Медленный читатель замедляет скан, но не
// приводит к росту памяти.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (<-chan Result, error) {
	targets, hostsErr := parseTargets(hosts)
	var errs []error
	if hostsErr != nil {
		errs = append(errs, hostsErr)
	}
	if err := ports.Err(); err != nil {
		errs = append(errs, err)
	}
	if err := joinErrors(errs); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	out := make(chan Result, min(s.cfg.concurrency, maxResultBuffer))
	go s.run(ctx, targets, ports, out)
	return out, nil
}

// run ведёт весь скан и в конце закрывает out: больше никто его не закрывает.
func (s *Scanner) run(ctx context.Context, targets []target, ports PortSet, out chan<- Result) {
	defer close(out)

	endpoints, failed, err := resolve(ctx, s.cfg.resolver, targets, min(s.cfg.concurrency, maxResolveWorkers))
	if err != nil {
		return // отмена во время резолвинга
	}
	for _, r := range failed {
		if !deliver(ctx, out, r) {
			return
		}
	}
	s.scanPorts(ctx, endpoints, ports, out)
}

type job struct {
	ep   endpoint
	port uint16
}

// scanPorts раздаёт задачи воркерам и ждёт их завершения.
func (s *Scanner) scanPorts(ctx context.Context, endpoints []endpoint, ports PortSet, out chan<- Result) {
	total := int64(len(endpoints)) * int64(ports.count())
	if total == 0 {
		return
	}
	workers := int(min(int64(s.cfg.concurrency), total))

	jobs := make(chan job)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for j := range jobs {
				res, ok := s.check(ctx, j)
				if ok {
					deliver(ctx, out, res)
				}
			}
		})
	}

	produce(ctx, endpoints, ports, jobs)
	close(jobs)
	wg.Wait()
}

// produce отдаёт задачи в jobs по одной, пока не кончатся или не отменят ctx.
// Порты снаружи, адреса внутри: нагрузка делится между хостами, а не бьёт
// в один. Списка host x port в памяти нет.
func produce(ctx context.Context, endpoints []endpoint, ports PortSet, jobs chan<- job) {
	for port := range ports.all() {
		for _, ep := range endpoints {
			// без этой проверки select при готовых обеих ветках выбирает
			// случайную, и после отмены ещё несколько задач ушло бы воркерам
			if ctx.Err() != nil {
				return
			}
			select {
			case jobs <- job{ep: ep, port: port}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// check занимает слот и проверяет порт. Слот держится только на время
// подключения, а не пока результат ждёт читателя: иначе один зависший
// читатель блокировал бы остальные Scan этого Scanner.
// Вторым значением false, если скан отменили, пока ждали слот.
func (s *Scanner) check(ctx context.Context, j job) (Result, bool) {
	if ctx.Err() != nil {
		return Result{}, false
	}
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return Result{}, false
	}
	defer func() { <-s.sem }()
	return probe(ctx, s.cfg.dialer, j.ep, j.port, s.cfg.timeout), true
}

// deliver отдаёт результат читателю. Если читатель не успевает, а ctx
// отменён, результат отбрасывается и возвращается false: так брошенный
// канал не держит горутины. Пока место или читатель есть, отмена
// результат не отбрасывает.
func deliver(ctx context.Context, out chan<- Result, r Result) bool {
	select {
	case out <- r:
		return true
	default:
	}
	select {
	case out <- r:
		return true
	case <-ctx.Done():
		return false
	}
}
