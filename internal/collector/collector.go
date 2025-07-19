// 文件路径: internal/collector/collector.go

package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// 【最终版本】: go:generate指令是简洁的版本，因为它依赖于旁边手动生成的vmlinux.h
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" bpf ./bpf/probe.c -- -I./bpf

// TrafficEvent 对应于 C 代码中的 struct traffic_event
// 我们必须确保Go结构体在内存布局上与C结构体完全匹配
type TrafficEvent struct {
	Bytes uint64
	Pid   uint32
	Comm  [16]byte
	IsTx  bool
	// C的bool是1字节，Go的bool也是1字节，但为了对齐，后面会有3个填充字节
	// 我们需要显式地添加它们以确保内存布局一致
	_ [3]byte // Padding
}

// CommToString 将C语言的char数组转换为Go的string
func (te *TrafficEvent) CommToString() string {
	return strings.TrimRight(string(te.Comm[:]), "\x00")
}

// Collector 是我们的主采集器结构体
type Collector struct {
	eventsChan chan TrafficEvent
	stopChan   chan struct{}
}

// NewCollector 创建一个新的采集器实例
func NewCollector(eventsChan chan TrafficEvent) *Collector {
	return &Collector{
		eventsChan: eventsChan,
		stopChan:   make(chan struct{}),
	}
}

// Start 启动eBPF探针并开始监听事件
func (c *Collector) Start() error {
	log.Println("Starting eBPF collector...")

	// 监听中断信号，以便优雅地关闭
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 使用 go:generate 生成的 bpfObjects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading bpf objects: %w", err)
	}
	defer objs.Close()

	// 附加 TX kprobe
	txProbe, err := link.Kprobe("net_dev_start_xmit", objs.ProbeTx, nil)
	if err != nil {
		return fmt.Errorf("attaching tx kprobe: %w", err)
	}
	defer txProbe.Close()
	log.Println("TX probe attached.")

	// 附加 RX kprobe
	rxProbe, err := link.Kprobe("netif_receive_skb", objs.ProbeRx, nil)
	if err != nil {
		return fmt.Errorf("attaching rx kprobe: %w", err)
	}
	defer rxProbe.Close()
	log.Println("RX probe attached.")

	// 创建一个 Perf Event Reader 来从内核读取数据
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf event reader: %w", err)
	}
	defer rd.Close()

	log.Println("Collector started successfully. Waiting for events...")

	// 启动一个goroutine来处理关闭和信号
	go func() {
		select {
		case <-stopper:
			log.Println("Received stop signal, shutting down...")
			close(c.stopChan)
		case <-c.stopChan:
		}
		rd.Close()
	}()

	// 主循环，读取和解析事件
	var event TrafficEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Perf reader closed.")
				return nil
			}
			log.Printf("Error reading from perf reader: %v", err)
			continue
		}

		if record.LostSamples > 0 {
			log.Printf("Perf event ring buffer full, lost %d samples", record.LostSamples)
			continue
		}

		// 将原始字节数据解析到我们的Go结构体中
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Error parsing perf event: %v", err)
			continue
		}

		// 将解析后的事件发送到 channel
		c.eventsChan <- event
	}
}

// Stop 停止采集器
func (c *Collector) Stop() {
	close(c.stopChan)
}
