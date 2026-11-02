package portscan

import "errors"

// Ошибки при задании портов. Проверять через errors.Is.
var (
	ErrNoPorts      = errors.New("portscan: no ports to scan")   // набор пустой
	ErrInvalidPort  = errors.New("portscan: invalid port")       // не в 1-65535 или не число
	ErrInvalidRange = errors.New("portscan: invalid port range") // обратный или кривой диапазон
)

// Ошибки при задании хостов.
var (
	ErrNoTargets   = errors.New("portscan: no hosts to scan") // список хостов пуст
	ErrEmptyHost   = errors.New("portscan: empty host")       // пустая строка или одни пробелы
	ErrInvalidHost = errors.New("portscan: invalid host")     // не IP-адрес и не имя хоста

	// ErrUnresolvable приходит не из Scan, а в Result.Err: DNS не нашёл имя
	// или вернул пустой ответ.
	ErrUnresolvable = errors.New("portscan: host cannot be resolved")
)
