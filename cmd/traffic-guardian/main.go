// cmd/traffic-guardian/main.go
package main

import (
	"fmt"
	"strings"
	"traffic-guardian/internal/collector"
)

func main() {
	// 创建一个足够大的channel来接收事件
	eventsChan := make(chan collector.TrafficEvent, 1000)

	// 实例化并启动采集器
	coll := collector.NewCollector(eventsChan)
	go func() {
		if err := coll.Start(); err != nil {
			fmt.Printf("Failed to start collector: %v\n", err)
		}
	}()

	fmt.Println("Collector is running. Try generating some network traffic (e.g., ping google.com)...")

	// 从channel中读取并打印事件
	for event := range eventsChan {
		comm := strings.TrimRight(string(event.Comm[:]), "\x00")
		direction := "RX"
		if event.IsTx {
			direction = "TX"
		}
		fmt.Printf("PID: %-6d Comm: %-16s Direction: %-3s Bytes: %d\n",
			event.Pid, comm, direction, event.Bytes)
	}
}
