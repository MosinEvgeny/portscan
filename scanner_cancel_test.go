package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

func TestScan_ReaderGoneThenCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(4))
		ctx, cancel := context.WithCancel(bg)
		ch := mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 1000))

		time.Sleep(time.Second) // читатель молчит, воркеры ждут его
		synctest.Wait()
		cancel()
		synctest.Wait() // все горутины скана должны выйти сами

		// то, что успело попасть в буфер, прочитать можно, дальше канал закрыт
		if n := len(collect(ch)); n > 4 {
			t.Errorf("после отмены осталось %d результатов, want не больше размера буфера (4)", n)
		}
		if started := d.started(); started > 8 {
			t.Errorf("начато %d подключений, want не больше 8", started)
		}
	})
}

func TestScan_CancelStopsTheScan(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{delay: 10 * time.Millisecond}
		s := newTestScanner(t, d, nil, WithConcurrency(5))
		ctx, cancel := context.WithCancel(bg)

		start := time.Now()
		ch := mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 10000))
		go func() {
			time.Sleep(35 * time.Millisecond)
			cancel()
		}()
		results := collect(ch)

		// к 35мс завершились 3 партии по 5, четвёртая (5 подключений) в процессе
		if n := count(results, StateClosed); n != 15 {
			t.Errorf("завершённых проверок %d, want 15", n)
		}
		if n := count(results, StateCanceled); n != 5 {
			t.Errorf("прерванных проверок %d, want 5", n)
		}
		for _, r := range results {
			if r.State == StateCanceled && !errors.Is(r.Err, context.Canceled) {
				t.Errorf("Err = %v, want context.Canceled", r.Err)
			}
		}
		// новые подключения после отмены не начинались
		if started := d.started(); started != 20 {
			t.Errorf("начато %d подключений, want 20", started)
		}
		// канал закрылся сразу, начатые операции не ждали своих 10мс
		if elapsed := time.Since(start); elapsed != 35*time.Millisecond {
			t.Errorf("скан завершился через %v, want 35ms", elapsed)
		}
	})
}

func TestScan_DeadlineIsCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{hang: true}
		s := newTestScanner(t, d, nil, WithConcurrency(3), WithConnectTimeout(time.Hour))
		ctx, cancel := context.WithTimeout(bg, 200*time.Millisecond)
		defer cancel()

		results := collect(mustScan(t, s, ctx, []string{"10.0.0.1"}, Range(1, 1000)))

		if count(results, StateCanceled) != 3 || len(results) != 3 {
			t.Errorf("results = %+v, want 3 canceled", results)
		}
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v", ctx.Err())
		}
	})
}

func TestScan_CancelDuringResolving(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fakeResolver{answers: map[string]answer{"slow.example": {block: true}}}
		d := &fakeDialer{}
		s := newTestScanner(t, d, r)
		ctx, cancel := context.WithCancel(bg)

		start := time.Now()
		ch := mustScan(t, s, ctx, []string{"slow.example", "10.0.0.1"}, Range(1, 100))
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()
		results := collect(ch)

		if len(results) != 0 {
			t.Errorf("results = %+v, want ничего", results)
		}
		if d.started() != 0 {
			t.Error("подключения начались до конца резолвинга")
		}
		if elapsed := time.Since(start); elapsed != time.Second {
			t.Errorf("канал закрылся через %v, want 1s", elapsed)
		}
	})
}

func TestScan_CancelWhileDeliveringResolveFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// неразрешённых имён больше, чем влезает в буфер, а читателя нет
		var hosts []string
		for i := range 30 {
			hosts = append(hosts, "n"+string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
		}
		s := newTestScanner(t, &fakeDialer{}, &fakeResolver{}, WithConcurrency(2)) // буфер 2
		ctx, cancel := context.WithCancel(bg)
		ch := mustScan(t, s, ctx, hosts, Ports(80))

		time.Sleep(time.Second)
		synctest.Wait()
		cancel()
		synctest.Wait()

		if n := len(collect(ch)); n > 2 {
			t.Errorf("после отмены осталось %d результатов, want не больше буфера (2)", n)
		}
	})
}

func TestScan_CancelWhileWaitingForSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Scan A держит оба слота зависшими подключениями, Scan B ждёт слот
		d := &fakeDialer{}
		hang := dialFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
			if ap, _ := netip.ParseAddrPort(a); ap.Addr() == addr("10.0.0.1") {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return d.DialContext(ctx, n, a)
		})
		s := newTestScanner(t, hang, nil, WithConcurrency(2), WithConnectTimeout(time.Hour))

		ctxA, cancelA := context.WithCancel(bg)
		chA := mustScan(t, s, ctxA, []string{"10.0.0.1"}, Range(1, 10))
		time.Sleep(time.Second)
		synctest.Wait()

		ctxB, cancelB := context.WithCancel(bg)
		chB := mustScan(t, s, ctxB, []string{"10.0.0.2"}, Range(1, 10))
		time.Sleep(time.Second)
		synctest.Wait()
		cancelB()

		if got := collect(chB); len(got) != 0 {
			t.Errorf("B: results = %+v, want ничего: слотов не было", got)
		}
		if d.started() != 0 {
			t.Error("B начал подключения, хотя слотов не было")
		}

		cancelA()
		collect(chA)
		if n := len(s.sem); n != 0 {
			t.Errorf("после обоих сканов занято слотов %d, want 0", n)
		}
	})
}

func TestProduce_NothingIsSentAfterCancel(t *testing.T) {
	// читатель уже ждёт задачу: без проверки ctx между задачами select
	// с равными шансами отдал бы часть задач и после отмены
	synctest.Test(t, func(t *testing.T) {
		for range 50 {
			jobs := make(chan job)
			received := make(chan int)
			go func() {
				n := 0
				for range jobs {
					n++
				}
				received <- n
			}()
			synctest.Wait() // читатель точно встал в ожидание

			produce(canceledCtx(), []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 1000), jobs)
			close(jobs)
			if n := <-received; n != 0 {
				t.Fatalf("после отмены отправлено %d задач, want 0", n)
			}
		}
	})
}

func TestProduce_StopsWhenCanceledInTheMiddle(t *testing.T) {
	ctx, cancel := context.WithCancel(bg)
	jobs := make(chan job)
	done := make(chan struct{})
	received := 0
	go func() {
		defer close(done)
		for range jobs {
			received++
			if received == 3 {
				cancel()
			}
		}
	}()
	produce(ctx, []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 1000), jobs)
	close(jobs)
	<-done
	// четвёртая могла уйти, пока cancel ещё не выполнился, пятая - уже нет
	if received < 3 || received > 4 {
		t.Errorf("отправлено %d задач, want 3 или 4", received)
	}
}

func TestProduce_ReturnsWhenNobodyTakesJobs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(bg)
		done := make(chan struct{})
		go func() {
			defer close(done)
			produce(ctx, []endpoint{{"a", addr("10.0.0.1")}}, Range(1, 10), make(chan job)) // читателя нет
		}()
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("produce вернулась без отмены")
		default:
		}
		cancel()
		<-done
	})
}

func TestCheck_CanceledBeforeStart(t *testing.T) {
	d := &fakeDialer{}
	s := newTestScanner(t, d, nil)
	// слот свободен и ctx отменён: select без проверки выбирал бы ветку
	// случайно, поэтому повторяем
	for range 50 {
		if _, ok := s.check(canceledCtx(), job{ep: endpoint{"a", addr("10.0.0.1")}, port: 80}); ok {
			t.Fatal("check при отменённом ctx вернула результат")
		}
	}
	if d.started() != 0 {
		t.Error("подключение началось при отменённом ctx")
	}
	if n := len(s.sem); n != 0 {
		t.Errorf("занято слотов %d, want 0", n)
	}
}

func TestCheck_CanceledWhileWaitingForSlot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d := &fakeDialer{}
		s := newTestScanner(t, d, nil, WithConcurrency(2))
		s.sem <- struct{}{} // оба слота заняты кем-то другим
		s.sem <- struct{}{}

		ctx, cancel := context.WithCancel(bg)
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		_, ok := s.check(ctx, job{ep: endpoint{"a", addr("10.0.0.1")}, port: 80})

		if ok {
			t.Error("check вернула результат, хотя слот так и не освободился")
		}
		if elapsed := time.Since(start); elapsed != 10*time.Millisecond {
			t.Errorf("check вернулась через %v, want 10ms", elapsed)
		}
		if d.started() != 0 {
			t.Error("подключение началось без слота")
		}
		if n := len(s.sem); n != 2 {
			t.Errorf("слотов занято %d, want 2: чужие слоты не должны освобождаться", n)
		}
	})
}
