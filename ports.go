package portscan

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
)

const (
	minPort = 1
	maxPort = 65535
)

// отрезок портов, границы включительно
type portRange struct{ lo, hi uint16 }

// PortSet - неизменяемый набор портов, нулевое значение - пустой набор.
//
// Конструкторы ошибку не возвращают: она сохраняется в наборе
// (сам набор при этом пустой) и выходит из Err и из Scan.
type PortSet struct {
	// отсортированные, непересекающиеся и несмежные отрезки
	ranges []portRange
	err    error
}

// Ports - набор из отдельных портов, допустимы 1-65535.
func Ports(ports ...int) PortSet {
	ranges := make([]portRange, 0, len(ports))
	var errs []error
	for _, p := range ports {
		if err := checkPort(p); err != nil {
			errs = append(errs, err)
			continue
		}
		ranges = append(ranges, portRange{uint16(p), uint16(p)})
	}
	return newPortSet(ranges, errs)
}

// Range - порты от from до to включительно.
// Обратный диапазон (1000, 1) - это ErrInvalidRange, местами не меняем.
func Range(from, to int) PortSet {
	var errs []error
	for _, p := range [...]int{from, to} {
		if err := checkPort(p); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 && from > to {
		errs = append(errs, fmt.Errorf("%w: %d-%d (start is greater than end)", ErrInvalidRange, from, to))
	}
	if len(errs) > 0 {
		return newPortSet(nil, errs)
	}
	return newPortSet([]portRange{{uint16(from), uint16(to)}}, nil)
}

// Union объединяет наборы. Если в каком-то из них ошибка, она будет и в результате.
func Union(sets ...PortSet) PortSet {
	var (
		ranges []portRange
		errs   []error
	)
	for _, s := range sets {
		ranges = append(ranges, s.ranges...) // append копирует, общей памяти с аргументами нет
		if s.err != nil {
			errs = append(errs, s.err)
		}
	}
	return newPortSet(ranges, errs)
}

// ParsePorts разбирает список вида "22,80,8000-8100".
// Возвращаемый набор хранит ту же ошибку, что и err.
func ParsePorts(spec string) (PortSet, error) {
	if strings.TrimSpace(spec) == "" {
		set := PortSet{}
		return set, set.Err()
	}
	var sets []PortSet
	for element := range strings.SplitSeq(spec, ",") {
		sets = append(sets, parseElement(strings.TrimSpace(element)))
	}
	set := Union(sets...)
	return set, set.Err()
}

// Err возвращает nil, если набор можно сканировать: он не пустой и без ошибок.
func (s PortSet) Err() error {
	if s.err != nil {
		return s.err
	}
	if len(s.ranges) == 0 {
		return ErrNoPorts
	}
	return nil
}

// String возвращает каноничную запись, например "22,80,8000-8100".
func (s PortSet) String() string {
	var b strings.Builder
	for i, r := range s.ranges {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(int(r.lo)))
		if r.hi != r.lo {
			b.WriteByte('-')
			b.WriteString(strconv.Itoa(int(r.hi)))
		}
	}
	return b.String()
}

// all отдаёт порты по возрастанию, срез не выделяется
func (s PortSet) all() iter.Seq[uint16] {
	return func(yield func(uint16) bool) {
		for _, r := range s.ranges {
			// int, а не uint16: иначе цикл не закончится на 65535
			for p := int(r.lo); p <= int(r.hi); p++ {
				if !yield(uint16(p)) {
					return
				}
			}
		}
	}
}

func (s PortSet) count() int {
	n := 0
	for _, r := range s.ranges {
		n += int(r.hi) - int(r.lo) + 1
	}
	return n
}

// newPortSet забирает ranges себе. При ошибке набор пустой.
func newPortSet(ranges []portRange, errs []error) PortSet {
	if err := joinErrors(errs); err != nil {
		return PortSet{err: err}
	}
	return PortSet{ranges: mergeRanges(ranges)}
}

// mergeRanges сортирует и склеивает пересекающиеся и соседние отрезки:
// 1-10 и 11-20 дают 1-20. Работает на месте.
func mergeRanges(ranges []portRange) []portRange {
	if len(ranges) == 0 {
		return nil
	}
	slices.SortFunc(ranges, func(a, b portRange) int { return cmp.Compare(a.lo, b.lo) })
	merged := ranges[:1]
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		// int, иначе last.hi+1 переполнится на 65535
		if int(r.lo) <= int(last.hi)+1 {
			last.hi = max(last.hi, r.hi)
			continue
		}
		merged = append(merged, r)
	}
	return slices.Clip(merged)
}

// parseElement разбирает один элемент списка: "80" или "8000-8100".
func parseElement(element string) PortSet {
	if element == "" {
		return PortSet{err: fmt.Errorf("%w: empty element in the port list", ErrInvalidPort)}
	}

	startStr, endStr, isRange := strings.Cut(element, "-")
	if !isRange {
		if !isDigits(element) {
			return PortSet{err: fmt.Errorf("%w: %q is not a number", ErrInvalidPort, element)}
		}
		p, err := atoiPort(element)
		if err != nil {
			return PortSet{err: err}
		}
		return Ports(p)
	}

	startStr, endStr = strings.TrimSpace(startStr), strings.TrimSpace(endStr)
	if !isDigits(startStr) || !isDigits(endStr) {
		return PortSet{err: fmt.Errorf("%w: malformed range %q", ErrInvalidRange, element)}
	}
	start, errStart := atoiPort(startStr)
	end, errEnd := atoiPort(endStr)
	if err := errors.Join(errStart, errEnd); err != nil {
		return PortSet{err: err}
	}
	return Range(start, end)
}

func checkPort(p int) error {
	if p < minPort || p > maxPort {
		return fmt.Errorf("%w: %d (valid ports are %d-%d)", ErrInvalidPort, p, minPort, maxPort)
	}
	return nil
}

// isDigits: только ASCII-цифры, без знака, пробелов и префиксов
func isDigits(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
}

// atoiPort: s - только цифры, ошибка бывает лишь при переполнении int
func atoiPort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%w: %s is out of range (valid ports are %d-%d)", ErrInvalidPort, s, minPort, maxPort)
	}
	return n, nil
}

func joinErrors(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}
