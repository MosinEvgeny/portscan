package portscan

import "errors"

// Ошибки при задании портов. Проверять через errors.Is.
var (
	ErrNoPorts      = errors.New("portscan: no ports to scan")   // набор пустой
	ErrInvalidPort  = errors.New("portscan: invalid port")       // не в 1-65535 или не число
	ErrInvalidRange = errors.New("portscan: invalid port range") // обратный или кривой диапазон
)
