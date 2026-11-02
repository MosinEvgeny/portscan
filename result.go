package portscan

import (
	"net/netip"
	"time"
)

// State - состояние порта.
type State uint8

const (
	StateUnknown     State = iota // нулевое значение, проверка его не возвращает
	StateOpen                     // соединение установлено
	StateClosed                   // соединение отклонено
	StateTimeout                  // не уложились в таймаут подключения
	StateUnreachable              // хост или сеть недоступны
	StateCanceled                 // проверка отменена через context
	StateError                    // любая другая ошибка
)

func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	}
	return "unknown"
}

// Result - итог проверки одного порта.
//
// Если имя хоста не разрешилось, по нему приходит один Result с Port == 0,
// пустым IP, State == StateError и Err, которая оборачивает ErrUnresolvable.
type Result struct {
	Host     string     // как передан в Scan, без пробелов по краям
	IP       netip.Addr // адрес, который проверяли
	Port     uint16
	State    State
	Duration time.Duration // время подключения, для неразрешённого хоста - время резолвинга
	Err      error         // у открытого порта nil, иначе причина
}
