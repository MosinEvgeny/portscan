package portscan

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
)

func TestPortSet_ZeroValue(t *testing.T) {
	var s PortSet
	if !errors.Is(s.Err(), ErrNoPorts) {
		t.Errorf("Err() = %v, want ErrNoPorts", s.Err())
	}
	if got := s.String(); got != "" {
		t.Errorf("String() = %q, want empty", got)
	}
	if n := s.count(); n != 0 {
		t.Errorf("count() = %d, want 0", n)
	}
	if got := slices.Collect(s.all()); len(got) != 0 {
		t.Errorf("all() = %v, want nothing", got)
	}
}

func TestPorts(t *testing.T) {
	tests := []struct {
		name string
		in   []int
		want string
	}{
		{"один порт", []int{80}, "80"},
		{"сортируются", []int{443, 22, 80}, "22,80,443"},
		{"дубли убираются", []int{80, 80, 443, 80}, "80,443"},
		{"соседние сливаются", []int{3, 1, 2}, "1-3"},
		{"крайние порты", []int{1, 65535}, "1,65535"},
		{"соседние у верхней границы", []int{65535, 65534}, "65534-65535"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Ports(tt.in...)
			if err := s.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
			if got := s.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPorts_Empty(t *testing.T) {
	if err := Ports().Err(); !errors.Is(err, ErrNoPorts) {
		t.Errorf("Err() = %v, want ErrNoPorts", err)
	}
}

func TestPorts_Invalid(t *testing.T) {
	tests := []struct {
		name string
		in   []int
	}{
		{"порт 0", []int{0}},
		{"отрицательный", []int{-1}},
		{"больше 65535", []int{65536}},
		{"очень большой", []int{math.MaxInt}},
		{"невалидный среди валидных", []int{80, 0, 443}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Ports(tt.in...)
			if err := s.Err(); !errors.Is(err, ErrInvalidPort) {
				t.Fatalf("Err() = %v, want ErrInvalidPort", err)
			}
			// невалидный набор пустой
			if got := s.String(); got != "" {
				t.Errorf("String() = %q, want empty", got)
			}
		})
	}
}

func TestPorts_AllProblemsAreReported(t *testing.T) {
	err := Ports(80, 0, 70000, 443, -5).Err()
	if !errors.Is(err, ErrInvalidPort) {
		t.Fatalf("Err() = %v, want ErrInvalidPort", err)
	}
	for _, want := range []string{"0 (", "70000", "-5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestRange(t *testing.T) {
	tests := []struct {
		name     string
		from, to int
		want     string
		count    int
	}{
		{"обычный диапазон", 1, 1000, "1-1000", 1000},
		{"один порт", 80, 80, "80", 1},
		{"все порты", 1, 65535, "1-65535", 65535},
		{"верхняя граница", 65530, 65535, "65530-65535", 6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Range(tt.from, tt.to)
			if err := s.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
			if got := s.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got := s.count(); got != tt.count {
				t.Errorf("count() = %d, want %d", got, tt.count)
			}
		})
	}
}

func TestRange_IsStoredCompactly(t *testing.T) {
	// память не должна зависеть от числа портов
	if n := len(Range(1, 65535).ranges); n != 1 {
		t.Errorf("Range(1, 65535) uses %d ranges, want 1", n)
	}
}

func TestRange_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		from, to int
		want     error
		notWant  error
	}{
		{"начало 0", 0, 10, ErrInvalidPort, ErrInvalidRange},
		{"конец больше 65535", 1, 65536, ErrInvalidPort, ErrInvalidRange},
		{"оба отрицательные", -5, -1, ErrInvalidPort, ErrInvalidRange},
		{"обратный диапазон", 1000, 1, ErrInvalidRange, ErrInvalidPort},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Range(tt.from, tt.to)
			err := s.Err()
			if !errors.Is(err, tt.want) {
				t.Errorf("Err() = %v, want %v", err, tt.want)
			}
			if errors.Is(err, tt.notWant) {
				t.Errorf("Err() = %v, must not be %v", err, tt.notWant)
			}
			if got := s.String(); got != "" {
				t.Errorf("String() = %q, want empty", got)
			}
		})
	}
}

func TestUnion(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want string
	}{
		{"непересекающиеся", Union(Range(1, 10), Range(20, 30)), "1-10,20-30"},
		{"пересекающиеся", Union(Range(1, 10), Range(5, 20)), "1-20"},
		{"соседние", Union(Range(1, 10), Range(11, 20)), "1-20"},
		{"вложенный", Union(Range(1, 100), Range(10, 20)), "1-100"},
		{"аргументы не по порядку", Union(Range(100, 200), Range(1, 10)), "1-10,100-200"},
		{"порты и диапазоны", Union(Ports(22, 80), Range(8000, 8100), Ports(443)), "22,80,443,8000-8100"},
		{"пустые наборы игнорируются", Union(PortSet{}, Ports(80), PortSet{}), "80"},
		{"65535 внутри полного диапазона", Union(Range(1, 65535), Ports(65535)), "1-65535"},
		{"один аргумент", Union(Ports(8080, 80)), "80,8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.set.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
			if got := tt.set.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnion_Errors(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want []error
	}{
		{"нечего объединять", Union(), []error{ErrNoPorts}},
		{"только пустой набор", Union(PortSet{}), []error{ErrNoPorts}},
		{"неверный порт", Union(Ports(80), Ports(0)), []error{ErrInvalidPort}},
		{"неверный диапазон", Union(Range(1, 10), Range(5, 1)), []error{ErrInvalidRange}},
		{"обе ошибки", Union(Range(5, 1), Ports(0)), []error{ErrInvalidRange, ErrInvalidPort}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.set.Err()
			for _, want := range tt.want {
				if !errors.Is(err, want) {
					t.Errorf("Err() = %v, want it to wrap %v", err, want)
				}
			}
			if got := tt.set.String(); got != "" {
				t.Errorf("String() = %q, want empty", got)
			}
		})
	}
}

func TestUnion_DoesNotShareStorageWithArguments(t *testing.T) {
	a := Ports(1, 3) // два отрезка: "1,3"
	u := Union(a)
	u.ranges[0].hi = 9
	if got := a.String(); got != "1,3" {
		t.Errorf("modifying the union changed its argument: %q", got)
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		spec string
		want string
	}{
		{"80", "80"},
		{"80,443", "80,443"},
		{" 80 , 443 ", "80,443"},
		{"443,80", "80,443"},
		{"80,80", "80"},
		{"1-1024", "1-1024"},
		{"1 - 100", "1-100"},
		{"22,80,8000-8100", "22,80,8000-8100"},
		{"1000-2000,1500-2500", "1000-2500"},
		{"0080", "80"},
		{"65535", "65535"},
		{"1-65535", "1-65535"},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			s, err := ParsePorts(tt.spec)
			if err != nil {
				t.Fatalf("ParsePorts(%q) error = %v", tt.spec, err)
			}
			if got := s.String(); got != tt.want {
				t.Errorf("ParsePorts(%q) = %q, want %q", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParsePorts_Invalid(t *testing.T) {
	tests := []struct {
		spec string
		want error
	}{
		// пустые
		{"", ErrNoPorts},
		{"   ", ErrNoPorts},
		// пустые элементы
		{",", ErrInvalidPort},
		{"80,", ErrInvalidPort},
		{",80", ErrInvalidPort},
		{"80,,443", ErrInvalidPort},
		// не числа
		{"abc", ErrInvalidPort},
		{"+80", ErrInvalidPort},
		{"0x50", ErrInvalidPort},
		{"80 443", ErrInvalidPort},
		{"８０", ErrInvalidPort}, // цифры в полной ширине
		// вне диапазона
		{"0", ErrInvalidPort},
		{"65536", ErrInvalidPort},
		{"99999999999999999999", ErrInvalidPort},
		{"0-10", ErrInvalidPort},
		{"1-70000", ErrInvalidPort},
		{"1-99999999999999999999", ErrInvalidPort},
		{"99999999999999999999-5", ErrInvalidPort},
		// кривые и обратные диапазоны
		{"-1", ErrInvalidRange},
		{"-80", ErrInvalidRange},
		{"80-", ErrInvalidRange},
		{"1-2-3", ErrInvalidRange},
		{"a-b", ErrInvalidRange},
		{"1000-1", ErrInvalidRange},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			s, err := ParsePorts(tt.spec)
			if !errors.Is(err, tt.want) {
				t.Fatalf("ParsePorts(%q) error = %v, want %v", tt.spec, err, tt.want)
			}
			// набор несёт ту же ошибку
			if !errors.Is(s.Err(), tt.want) {
				t.Errorf("set.Err() = %v, want %v", s.Err(), tt.want)
			}
		})
	}
}

func TestParsePorts_AllProblemsAreReported(t *testing.T) {
	_, err := ParsePorts("80,abc,70000,5-1")
	if !errors.Is(err, ErrInvalidPort) || !errors.Is(err, ErrInvalidRange) {
		t.Fatalf("error = %v, want both ErrInvalidPort and ErrInvalidRange", err)
	}
	for _, want := range []string{"abc", "70000", "5-1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestPortSet_StringRoundTrip(t *testing.T) {
	sets := []PortSet{
		Ports(80),
		Range(1, 65535),
		Union(Ports(22, 80, 443), Range(8000, 8100), Range(9000, 9000)),
		Union(Range(1, 10), Range(20, 30), Ports(65535)),
	}
	for _, s := range sets {
		again, err := ParsePorts(s.String())
		if err != nil {
			t.Errorf("ParsePorts(%q) error = %v", s.String(), err)
			continue
		}
		if again.String() != s.String() {
			t.Errorf("round trip of %q gave %q", s.String(), again.String())
		}
	}
}

func TestPortSet_AllIsAscendingAndComplete(t *testing.T) {
	s := Union(Ports(443, 22), Range(8000, 8003))
	want := []uint16{22, 443, 8000, 8001, 8002, 8003}
	if got := slices.Collect(s.all()); !slices.Equal(got, want) {
		t.Errorf("all() = %v, want %v", got, want)
	}
	if got := s.count(); got != len(want) {
		t.Errorf("count() = %d, want %d", got, len(want))
	}
}

func TestPortSet_AllReachesPort65535(t *testing.T) {
	// цикл по uint16 тут бы завис
	got := slices.Collect(Range(65530, 65535).all())
	want := []uint16{65530, 65531, 65532, 65533, 65534, 65535}
	if !slices.Equal(got, want) {
		t.Errorf("all() = %v, want %v", got, want)
	}
	if n := len(slices.Collect(Range(1, 65535).all())); n != 65535 {
		t.Errorf("all() over 1-65535 yielded %d ports, want 65535", n)
	}
}

func TestPortSet_AllStopsWhenAsked(t *testing.T) {
	var got []uint16
	for p := range Range(1, 100).all() {
		got = append(got, p)
		if len(got) == 3 {
			break
		}
	}
	if want := []uint16{1, 2, 3}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestPorts_EveryPortInAnyOrder(t *testing.T) {
	// максимальный вход в худшем порядке
	in := make([]int, 0, 65535)
	for p := 65535; p >= 1; p-- {
		in = append(in, p)
	}
	s := Ports(in...)
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v", err)
	}
	if got := s.String(); got != "1-65535" {
		t.Errorf("String() = %q, want 1-65535", got)
	}
	if n := len(s.ranges); n != 1 {
		t.Errorf("uses %d ranges, want 1", n)
	}
}

func FuzzParsePorts(f *testing.F) {
	for _, seed := range []string{
		"", "80", "1-1024", "22,80,8000-8100", "1000-1", "0", "65536",
		"a-b", ",", " 80 , 443 ", "1-2-3", "99999999999999999999", "-", "--",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		set, err := ParsePorts(spec)

		// набор и err согласованы
		if (err == nil) != (set.Err() == nil) {
			t.Fatalf("ParsePorts(%q): err = %v but set.Err() = %v", spec, err, set.Err())
		}
		if err != nil {
			if set.count() != 0 {
				t.Fatalf("ParsePorts(%q): invalid set is not empty", spec)
			}
			return
		}

		// валидный набор: не пустой, отсортирован, склеен, в границах
		if set.count() == 0 {
			t.Fatalf("ParsePorts(%q): valid set is empty", spec)
		}
		prevHi := -2
		for _, r := range set.ranges {
			if r.lo < minPort || r.lo > r.hi {
				t.Fatalf("ParsePorts(%q): bad range %v", spec, r)
			}
			if int(r.lo) <= prevHi+1 {
				t.Fatalf("ParsePorts(%q): ranges are not sorted and merged: %v", spec, set.ranges)
			}
			prevHi = int(r.hi)
		}

		// каноничная запись разбирается обратно в тот же набор
		again, err := ParsePorts(set.String())
		if err != nil || again.String() != set.String() {
			t.Fatalf("ParsePorts(%q): round trip of %q gave %q, %v", spec, set.String(), again.String(), err)
		}
	})
}
