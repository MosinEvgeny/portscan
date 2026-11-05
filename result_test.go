package portscan

import (
	"encoding/json"
	"testing"
)

func TestState_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s    State
		want string
	}{
		{StateOpen, "open"},
		{StateClosed, "closed"},
		{StateTimeout, "timeout"},
		{StateUnreachable, "unreachable"},
		{StateCanceled, "canceled"},
		{StateError, "error"},
		{StateUnknown, "unknown"},
		{State(200), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestState_ZeroValueIsNotOpen(t *testing.T) {
	t.Parallel()
	var r Result
	if r.State == StateOpen {
		t.Error("пустой Result выглядит как открытый порт")
	}
	if r.State != StateUnknown {
		t.Errorf("State = %v, want unknown", r.State)
	}
}

func TestState_MarshalText(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(struct{ State State }{StateTimeout})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"State":"timeout"}`; got != want {
		t.Errorf("json = %s, want %s", got, want)
	}
}
