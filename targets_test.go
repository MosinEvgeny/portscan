package portscan

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func hostsOf(targets []target) []string {
	var hosts []string
	for _, t := range targets {
		hosts = append(hosts, t.host)
	}
	return hosts
}

func TestParseTargets_Valid(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string // host у оставшихся целей
	}{
		{"IPv4", []string{"192.168.1.10"}, []string{"192.168.1.10"}},
		{"IPv6", []string{"::1", "2001:db8::1"}, []string{"::1", "2001:db8::1"}},
		{"IPv6 с zone", []string{"fe80::1%en0"}, []string{"fe80::1%en0"}},
		{"DNS-имя", []string{"example.com"}, []string{"example.com"}},
		{"пробелы по краям убираются", []string{"  example.com\t", " 10.0.0.1 "}, []string{"example.com", "10.0.0.1"}},
		{"одно слово", []string{"localhost"}, []string{"localhost"}},
		{"подчёркивание", []string{"my_service.internal"}, []string{"my_service.internal"}},
		{"punycode", []string{"xn--80ak6aa92e.com"}, []string{"xn--80ak6aa92e.com"}},
		{"точка в конце", []string{"example.com."}, []string{"example.com."}},
		{"метка в 63 символа", []string{strings.Repeat("a", 63) + ".com"}, []string{strings.Repeat("a", 63) + ".com"}},
		{"порядок сохраняется", []string{"b.com", "10.0.0.1", "a.com"}, []string{"b.com", "10.0.0.1", "a.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTargets(tt.in)
			if err != nil {
				t.Fatalf("parseTargets(%q) error = %v", tt.in, err)
			}
			if h := hostsOf(got); !slices.Equal(h, tt.want) {
				t.Errorf("hosts = %q, want %q", h, tt.want)
			}
		})
	}
}

func TestParseTargets_IPOrName(t *testing.T) {
	got, err := parseTargets([]string{"10.0.0.1", "example.com", "::1", "fe80::1%en0"})
	if err != nil {
		t.Fatal(err)
	}
	wantAddr := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		{}, // у имени адреса нет
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("fe80::1%en0"),
	}
	for i, tg := range got {
		if tg.addr != wantAddr[i] {
			t.Errorf("targets[%d].addr = %v, want %v", i, tg.addr, wantAddr[i])
		}
	}
}

func TestParseTargets_Duplicates(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"одинаковые IP", []string{"10.0.0.1", "10.0.0.1"}, []string{"10.0.0.1"}},
		{"IPv6 в разной записи", []string{"::1", "0:0:0:0:0:0:0:1", "0000::0001"}, []string{"::1"}},
		{"IPv4 в IPv6", []string{"1.2.3.4", "::ffff:1.2.3.4"}, []string{"1.2.3.4"}},
		{"IPv4 в IPv6 первым", []string{"::ffff:1.2.3.4", "1.2.3.4"}, []string{"::ffff:1.2.3.4"}},
		{"имена без учёта регистра", []string{"Example.COM", "example.com", "EXAMPLE.com"}, []string{"Example.COM"}},
		{"имя с точкой и без", []string{"example.com.", "example.com"}, []string{"example.com."}},
		{"пробелы не мешают", []string{"example.com", "  example.com  "}, []string{"example.com"}},
		{"разные zone - разные хосты", []string{"fe80::1%en0", "fe80::1%en1"}, []string{"fe80::1%en0", "fe80::1%en1"}},
		{"дубли вперемешку", []string{"a.com", "10.0.0.1", "A.com", "b.com", "10.0.0.1"}, []string{"a.com", "10.0.0.1", "b.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTargets(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if h := hostsOf(got); !slices.Equal(h, tt.want) {
				t.Errorf("hosts = %q, want %q", h, tt.want)
			}
		})
	}
}

func TestParseTargets_NoTargets(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		if _, err := parseTargets(in); !errors.Is(err, ErrNoTargets) {
			t.Errorf("parseTargets(%v) error = %v, want ErrNoTargets", in, err)
		}
	}
}

func TestParseTargets_EmptyHost(t *testing.T) {
	for _, h := range []string{"", " ", "\t\n"} {
		_, err := parseTargets([]string{h})
		if !errors.Is(err, ErrEmptyHost) {
			t.Errorf("parseTargets(%q) error = %v, want ErrEmptyHost", h, err)
		}
		if errors.Is(err, ErrInvalidHost) {
			t.Errorf("parseTargets(%q): пустой хост не должен быть ErrInvalidHost", h)
		}
	}
}

func TestParseTargets_InvalidHost(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		// кривые IP
		{"октет больше 255", "999.1.1.1"},
		{"три октета", "1.2.3"},
		{"пять октетов", "1.2.3.4.5"},
		{"одно число", "123"},
		{"ведущий ноль", "010.1.1.1"},
		{"кривой IPv6", "::g"},
		{"IPv6 в скобках", "[::1]"},
		{"zone у IPv4", "1.2.3.4%eth0"},
		// не хост, а что-то другое
		{"с портом", "example.com:80"},
		{"IPv4 с портом", "1.2.3.4:80"},
		{"CIDR", "10.0.0.0/24"},
		{"URL", "http://example.com"},
		{"с логином", "user@example.com"},
		// плохие имена
		{"пробел внутри", "exa mple.com"},
		{"не-ASCII", "пример.рф"},
		{"спецсимвол", "exa$mple.com"},
		{"метка начинается с дефиса", "-a.com"},
		{"метка кончается дефисом", "a-.com"},
		{"пустая метка", "a..com"},
		{"точка в начале", ".a.com"},
		{"две точки в конце", "a.com.."},
		{"одна точка", "."},
		{"метка в 64 символа", strings.Repeat("a", 64) + ".com"},
		{"имя длиннее 253", strings.Repeat("a.", 127) + "com"},
		{"TLD из цифр", "example.123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTargets([]string{tt.host})
			if !errors.Is(err, ErrInvalidHost) {
				t.Errorf("parseTargets(%q) error = %v, want ErrInvalidHost", tt.host, err)
			}
		})
	}
}

func TestParseTargets_HostnameLengthBoundary(t *testing.T) {
	// 253 символа - можно, 254 - нельзя
	label := strings.Repeat("a", 61)
	name253 := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".") // 61*4+3 = 247
	name253 += ".abcde"                                                                  // 247+6 = 253
	if len(name253) != 253 {
		t.Fatalf("тест неверно собран: len = %d", len(name253))
	}
	if _, err := parseTargets([]string{name253}); err != nil {
		t.Errorf("имя из 253 символов отвергнуто: %v", err)
	}
	if _, err := parseTargets([]string{name253 + "a"}); !errors.Is(err, ErrInvalidHost) {
		t.Errorf("имя из 254 символов: error = %v, want ErrInvalidHost", err)
	}
}

func TestParseTargets_AllProblemsAreReported(t *testing.T) {
	_, err := parseTargets([]string{"ok.com", "", "bad host", "999.1.1.1", "  "})
	if !errors.Is(err, ErrEmptyHost) || !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("error = %v, want ErrEmptyHost and ErrInvalidHost", err)
	}
	for _, want := range []string{"hosts[1]", `"bad host"`, `"999.1.1.1"`, "hosts[4]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestParseTargets_OneBadHostFailsEverything(t *testing.T) {
	// ошибки синтаксиса - fail-fast: годные хосты не возвращаются
	got, err := parseTargets([]string{"ok.com", "bad host"})
	if err == nil || got != nil {
		t.Errorf("got %v, %v; want nil and an error", got, err)
	}
}

func TestParseTargets_DoesNotKeepInput(t *testing.T) {
	in := []string{"a.com", "b.com"}
	got, err := parseTargets(in)
	if err != nil {
		t.Fatal(err)
	}
	in[0] = "changed.com"
	if got[0].host != "a.com" {
		t.Errorf("результат зависит от входного среза: %q", got[0].host)
	}
}

func FuzzParseTargets(f *testing.F) {
	for _, seed := range []string{
		"", " ", "example.com", "EXAMPLE.com.", "10.0.0.1", "::1", "::ffff:1.2.3.4",
		"fe80::1%en0", "999.1.1.1", "a..b", "-a", "[::1]", "host:80", "пример.рф", "1.2.3",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, host string) {
		got, err := parseTargets([]string{host})
		if err != nil {
			if got != nil {
				t.Fatalf("parseTargets(%q): ошибка вместе с результатом", host)
			}
			return
		}
		if len(got) != 1 {
			t.Fatalf("parseTargets(%q) вернул %d целей", host, len(got))
		}

		// хост принят: он либо IP, либо имя, прошедшее проверку
		tg := got[0]
		if tg.addr.IsValid() {
			if tg.addr.Is4In6() {
				t.Fatalf("parseTargets(%q): адрес %v не приведён к IPv4", host, tg.addr)
			}
		} else if !validHostname(strings.TrimSuffix(tg.host, ".")) {
			t.Fatalf("parseTargets(%q): принято невалидное имя %q", host, tg.host)
		}

		// повторный разбор даёт то же самое
		again, err := parseTargets([]string{tg.host})
		if err != nil || len(again) != 1 || again[0] != tg {
			t.Fatalf("parseTargets(%q): повторный разбор %q дал %v, %v", host, tg.host, again, err)
		}
	})
}
