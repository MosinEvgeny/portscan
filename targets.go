package portscan

import (
	"net/netip"
	"strings"
)

// target - один хост из списка пользователя
type target struct {
	host string     // как передали, без пробелов по краям
	addr netip.Addr // задан, если host - это IP-адрес, а не имя
}

// ключ для поиска дублей: IP или имя в нижнем регистре без точки в конце
type targetKey struct {
	addr netip.Addr
	name string
}

// parseTargets проверяет хосты и убирает дубли, в сеть не ходит.
// Ошибки по всем плохим хостам возвращаются вместе.
func parseTargets(hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrNoTargets
	}
	var (
		targets = make([]target, 0, len(hosts))
		seen    = make(map[targetKey]struct{}, len(hosts))
		errs    []error
	)
	for i, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			errs = append(errs, &HostError{Index: i, Host: hosts[i], Err: ErrEmptyHost})
			continue
		}
		t, key, ok := parseHost(h)
		if !ok {
			errs = append(errs, &HostError{Index: i, Host: hosts[i], Err: ErrInvalidHost})
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		targets = append(targets, t)
	}
	if err := joinErrors(errs); err != nil {
		return nil, err
	}
	return targets, nil
}

// parseHost определяет, чем является h: IP-адресом или именем.
func parseHost(h string) (target, targetKey, bool) {
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap() // ::ffff:1.2.3.4 и 1.2.3.4 - один хост
		if addr.IsUnspecified() {
			return target{}, targetKey{}, false // 0.0.0.0 и :: на деле значат localhost
		}
		return target{host: h, addr: addr}, targetKey{addr: addr}, true
	}
	name := strings.TrimSuffix(h, ".")
	if !validHostname(name) {
		return target{}, targetKey{}, false
	}
	return target{host: h}, targetKey{name: strings.ToLower(name)}, true
}

// validHostname проверяет имя по RFC 1123, плюс разрешено "_" (встречается
// во внутренних именах). Не-ASCII имена надо передавать в punycode.
func validHostname(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	// последняя часть из одних цифр - это кривой IP вроде 999.1.1.1, а не имя
	return !isDigits(labels[len(labels)-1])
}
