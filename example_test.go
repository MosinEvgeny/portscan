package portscan_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/MosinEvgeny/portscan"
)

func ExampleScanner_Scan() {
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"192.168.1.10", "scanme.example"}, portscan.Range(1, 1000))
	if err != nil {
		log.Fatal(err)
	}

	for r := range results {
		if errors.Is(r.Err, portscan.ErrUnresolvable) {
			fmt.Printf("%s: не удалось разрешить имя\n", r.Host)
			continue
		}
		if r.State == portscan.StateOpen {
			fmt.Printf("%s:%d %s\n", r.IP, r.Port, r.State)
		}
	}
}

func ExampleParsePorts() {
	ports, err := portscan.ParsePorts("443, 80, 8000-8100, 80")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ports)
	// Output: 80,443,8000-8100
}

func ExampleUnion() {
	ports := portscan.Union(
		portscan.Ports(22, 80, 443),
		portscan.Range(8000, 8100),
		portscan.Range(8050, 8200),
	)
	fmt.Println(ports)
	// Output: 22,80,443,8000-8200
}

func ExampleRange() {
	fmt.Println(portscan.Range(1000, 1).Err())
	// Output: portscan: invalid port range: 1000-1 (start is greater than end)
}
