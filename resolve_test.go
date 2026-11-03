package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestResolve_IPLiteralsNeedNoDNS(t *testing.T) {
	r := &fakeResolver{}
	eps, failed, err := resolve(context.Background(), r, mustTargets(t, "192.168.1.10", "::1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []endpoint{{"192.168.1.10", addr("192.168.1.10")}, {"::1", addr("::1")}}
	if !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
	if len(failed) != 0 {
		t.Errorf("failed = %v, want none", failed)
	}
	if len(r.calls) != 0 {
		t.Errorf("resolver вызван для IP-адресов: %v", r.calls)
	}
}

func TestResolve_NameWithSeveralAddresses(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{
		"example.com": {addrs: []netip.Addr{addr("2001:db8::1"), addr("93.184.216.35"), addr("93.184.216.34")}},
	}}
	eps, failed, err := resolve(context.Background(), r, mustTargets(t, "example.com"), 4)
	if err != nil || len(failed) != 0 {
		t.Fatalf("err = %v, failed = %v", err, failed)
	}
	// по одному endpoint на адрес, IPv4 раньше IPv6, Host - имя из списка
	want := []endpoint{
		{"example.com", addr("93.184.216.34")},
		{"example.com", addr("93.184.216.35")},
		{"example.com", addr("2001:db8::1")},
	}
	if !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
	if !slices.Equal(r.networks, []string{"ip"}) {
		t.Errorf("network = %q, want одну попытку с \"ip\"", r.networks)
	}
}

func TestResolve_UnresolvableDoesNotStopOthers(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{
		"good.example": {addrs: []netip.Addr{addr("10.0.0.5")}},
	}}
	eps, failed, err := resolve(context.Background(), r, mustTargets(t, "good.example", "bad.example", "1.1.1.1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	want := []endpoint{{"good.example", addr("10.0.0.5")}, {"1.1.1.1", addr("1.1.1.1")}}
	if !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}

	if len(failed) != 1 {
		t.Fatalf("failed = %v, want одну запись", failed)
	}
	f := failed[0]
	if f.Host != "bad.example" || f.IP.IsValid() || f.Port != 0 || f.State != StateError {
		t.Errorf("failed[0] = %+v", f)
	}
	if !errors.Is(f.Err, ErrUnresolvable) {
		t.Errorf("Err = %v, want ErrUnresolvable", f.Err)
	}
	// исходная ошибка DNS не потеряна
	var dnsErr *net.DNSError
	if !errors.As(f.Err, &dnsErr) || !dnsErr.IsNotFound {
		t.Errorf("Err = %v, want внутри *net.DNSError с IsNotFound", f.Err)
	}
}

func TestResolve_EmptyAnswerIsUnresolvable(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{"empty.example": {}}}
	eps, failed, err := resolve(context.Background(), r, mustTargets(t, "empty.example"), 1)
	if err != nil || len(eps) != 0 || len(failed) != 1 {
		t.Fatalf("eps = %v, failed = %v, err = %v", eps, failed, err)
	}
	if !errors.Is(failed[0].Err, ErrUnresolvable) || !strings.Contains(failed[0].Err.Error(), "empty.example") {
		t.Errorf("Err = %v", failed[0].Err)
	}
}

func TestResolve_ResolverErrorIsWrapped(t *testing.T) {
	errBoom := errors.New("boom")
	r := &fakeResolver{answers: map[string]answer{"x.example": {err: errBoom}}}
	_, failed, err := resolve(context.Background(), r, mustTargets(t, "x.example"), 1)
	if err != nil || len(failed) != 1 {
		t.Fatalf("failed = %v, err = %v", failed, err)
	}
	if !errors.Is(failed[0].Err, ErrUnresolvable) || !errors.Is(failed[0].Err, errBoom) {
		t.Errorf("Err = %v, want ErrUnresolvable и boom", failed[0].Err)
	}
}

func TestResolve_SameIPIsScannedOnce(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{
		"a.example": {addrs: []netip.Addr{addr("1.2.3.4")}},
		"b.example": {addrs: []netip.Addr{addr("1.2.3.4")}},
		"c.example": {addrs: []netip.Addr{addr("1.2.3.4"), addr("5.6.7.8")}},
	}}
	targets := mustTargets(t, "a.example", "b.example", "1.2.3.4", "c.example")
	eps, failed, err := resolve(context.Background(), r, targets, 4)
	if err != nil || len(failed) != 0 {
		t.Fatalf("err = %v, failed = %v", err, failed)
	}
	// 1.2.3.4 остаётся за первым, кто его дал
	want := []endpoint{{"a.example", addr("1.2.3.4")}, {"c.example", addr("5.6.7.8")}}
	if !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
}

func TestResolve_LiteralBeforeNameWins(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{
		"a.example": {addrs: []netip.Addr{addr("1.2.3.4")}},
	}}
	eps, _, err := resolve(context.Background(), r, mustTargets(t, "1.2.3.4", "a.example"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if want := []endpoint{{"1.2.3.4", addr("1.2.3.4")}}; !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
}

func TestResolve_AnswerIsCleaned(t *testing.T) {
	got := []netip.Addr{addr("::ffff:1.2.3.4"), addr("1.2.3.4"), {}, addr("1.2.3.4")}
	orig := slices.Clone(got)
	r := &fakeResolver{answers: map[string]answer{"dup.example": {addrs: got}}}

	eps, _, err := resolve(context.Background(), r, mustTargets(t, "dup.example"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []endpoint{{"dup.example", addr("1.2.3.4")}}; !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
	if !slices.Equal(got, orig) {
		t.Errorf("срез resolver-а изменён: %v, было %v", got, orig)
	}
}

func TestResolve_SameNameIsResolvedOnce(t *testing.T) {
	r := &fakeResolver{answers: map[string]answer{
		"A.example": {addrs: []netip.Addr{addr("1.2.3.4")}},
	}}
	targets := mustTargets(t, "A.example", "a.example", "a.example.")
	eps, _, err := resolve(context.Background(), r, targets, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.calls, []string{"A.example"}) {
		t.Errorf("calls = %q, want один вызов", r.calls)
	}
	if want := []endpoint{{"A.example", addr("1.2.3.4")}}; !slices.Equal(eps, want) {
		t.Errorf("endpoints = %v, want %v", eps, want)
	}
}

func TestResolve_NonPositiveParallelismStillWorks(t *testing.T) {
	for _, p := range []int{0, -1} {
		r := &fakeResolver{answers: map[string]answer{"a.example": {addrs: []netip.Addr{addr("1.2.3.4")}}}}
		eps, _, err := resolve(context.Background(), r, mustTargets(t, "a.example"), p)
		if err != nil || len(eps) != 1 {
			t.Errorf("parallelism %d: eps = %v, err = %v", p, eps, err)
		}
	}
}

func TestResolve_ResultsFollowInputOrder(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// чем раньше в списке, тем дольше отвечает: завершаются в обратном порядке
		r := &fakeResolver{answers: map[string]answer{
			"n0.example": {addrs: []netip.Addr{addr("10.0.0.0")}, delay: 50 * time.Millisecond},
			"n1.example": {addrs: []netip.Addr{addr("10.0.0.1")}, delay: 40 * time.Millisecond},
			"n2.example": {err: errors.New("boom"), delay: 30 * time.Millisecond},
			"n3.example": {addrs: []netip.Addr{addr("10.0.0.3")}, delay: 20 * time.Millisecond},
			"n4.example": {addrs: []netip.Addr{addr("10.0.0.4")}, delay: 10 * time.Millisecond},
		}}
		targets := mustTargets(t, "n0.example", "n1.example", "n2.example", "n3.example", "n4.example")
		eps, failed, err := resolve(context.Background(), r, targets, 5)
		if err != nil {
			t.Fatal(err)
		}

		wantDone := []string{"n4.example", "n3.example", "n2.example", "n1.example", "n0.example"}
		if !slices.Equal(r.done, wantDone) {
			t.Fatalf("done = %q, want %q (тест не проверяет порядок)", r.done, wantDone)
		}
		var hosts []string
		for _, ep := range eps {
			hosts = append(hosts, ep.host)
		}
		if want := []string{"n0.example", "n1.example", "n3.example", "n4.example"}; !slices.Equal(hosts, want) {
			t.Errorf("endpoints: %q, want %q", hosts, want)
		}
		if len(failed) != 1 || failed[0].Host != "n2.example" {
			t.Errorf("failed = %v", failed)
		}
	})
}

func TestResolve_ParallelismIsLimited(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		answers := map[string]answer{}
		var hosts []string
		for i := range 10 {
			h := "n" + string(rune('0'+i)) + ".example"
			hosts = append(hosts, h)
			answers[h] = answer{addrs: []netip.Addr{netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})}, delay: 10 * time.Millisecond}
		}
		r := &fakeResolver{answers: answers}

		start := time.Now()
		eps, _, err := resolve(context.Background(), r, mustTargets(t, hosts...), 3)
		if err != nil || len(eps) != 10 {
			t.Fatalf("eps = %d, err = %v", len(eps), err)
		}
		if r.maxInFlight != 3 {
			t.Errorf("одновременно %d запросов, want 3", r.maxInFlight)
		}
		// 10 имён по 3 за раз: 4 партии по 10мс
		if elapsed := time.Since(start); elapsed != 40*time.Millisecond {
			t.Errorf("заняло %v, want 40ms", elapsed)
		}
	})
}

func TestResolve_FailureDuration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fakeResolver{answers: map[string]answer{
			"slow.example": {err: errors.New("boom"), delay: 25 * time.Millisecond},
		}}
		_, failed, err := resolve(context.Background(), r, mustTargets(t, "slow.example"), 1)
		if err != nil || len(failed) != 1 {
			t.Fatalf("failed = %v, err = %v", failed, err)
		}
		if failed[0].Duration != 25*time.Millisecond {
			t.Errorf("Duration = %v, want 25ms", failed[0].Duration)
		}
	})
}

func TestResolve_CancelStopsEverything(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		answers := map[string]answer{}
		var hosts []string
		for i := range 10 {
			h := "n" + string(rune('0'+i)) + ".example"
			hosts = append(hosts, h)
			answers[h] = answer{block: true}
		}
		r := &fakeResolver{answers: answers}

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		start := time.Now()
		eps, failed, err := resolve(ctx, r, mustTargets(t, hosts...), 2)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if eps != nil || failed != nil {
			t.Errorf("после отмены вернулись данные: %v, %v", eps, failed)
		}
		if elapsed := time.Since(start); elapsed != 50*time.Millisecond {
			t.Errorf("вернулась через %v, want 50ms", elapsed)
		}
		// новые запросы после отмены не начинаются: были только 2 зависших
		if len(r.calls) != 2 {
			t.Errorf("начато %d запросов, want 2", len(r.calls))
		}
		// утечку горутин synctest найдёт сам: Test падает, если что-то осталось
	})
}

func TestResolve_AlreadyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, hosts := range [][]string{{"a.example", "b.example"}, {"10.0.0.1"}} {
		r := &fakeResolver{answers: map[string]answer{"a.example": {addrs: []netip.Addr{addr("1.2.3.4")}}}}
		eps, failed, err := resolve(ctx, r, mustTargets(t, hosts...), 2)
		if !errors.Is(err, context.Canceled) || eps != nil || failed != nil {
			t.Errorf("hosts %q: eps = %v, failed = %v, err = %v", hosts, eps, failed, err)
		}
	}
}

func TestResolve_CancelIsNotReportedAsUnresolvable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := &fakeResolver{answers: map[string]answer{"a.example": {block: true}}}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()
		_, failed, err := resolve(ctx, r, mustTargets(t, "a.example"), 1)
		if !errors.Is(err, context.Canceled) || failed != nil {
			t.Errorf("failed = %v, err = %v", failed, err)
		}
	})
}

func TestResolve_RealResolverLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	eps, failed, err := resolve(ctx, new(net.Resolver), mustTargets(t, "localhost"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) > 0 {
		t.Skipf("localhost не разрешается в этом окружении: %v", failed[0].Err)
	}
	for _, ep := range eps {
		if ep.host != "localhost" || !ep.ip.IsLoopback() {
			t.Errorf("endpoint %v: ожидался loopback-адрес для localhost", ep)
		}
	}
}
