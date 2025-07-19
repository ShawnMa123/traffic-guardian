// internal/collector/collector.go
package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ./bpf/probe.c -- -I./bpf/headers

// TrafficEvent mirrors the struct in probe.c
type TrafficEvent struct {
	PID uint32
	Len uint64
}

// Collector 负责管理 eBPF 程序
type Collector struct {
	log        *slog.Logger
	eventsChan chan<- TrafficEvent
}

// New 创建一个新的 Collector 实例
func New(log *slog.Logger, eventsChan chan<- TrafficEvent) *Collector {
	return &Collector{
		log:        log,
		eventsChan: eventsChan,
	}
}

// Start 启动 eBPF 采集器
func (c *Collector) Start(ctx context.Context) error {
	c.log.Info("Starting eBPF collector")

	// 加载 eBPF 程序和 maps (由 bpf2go 生成)
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	// 将 eBPF 程序附加到 tracepoint
	tp, err := link.Tracepoint("net", "net_dev_xmit", objs.HandleNetDevXmit, nil)
	if err != nil {
		return err
	}
	defer tp.Close()

	c.log.Info("eBPF program attached successfully")

	// 创建一个 perf event reader 来从内核读取数据
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return err
	}
	defer rd.Close()

	// 启动一个 goroutine 在后台处理关闭信号
	go func() {
		<-ctx.Done()
		rd.Close()
		c.log.Info("eBPF collector stopped")
	}()

	c.log.Info("Waiting for eBPF events...")

	// 主循环，读取和处理事件
	var event TrafficEvent
	for {
		record, err := rd.Read()
		if err != nil {
			// 当 rd.Close() 被调用时，会返回一个错误，我们检查上下文来判断是否是正常关闭
			if errors.Is(err, perf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			c.log.Error("Error reading from perf reader", "error", err)
			continue
		}

		// 解析数据
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			c.log.Error("Error parsing event data", "error", err)
			continue
		}

		// 将事件发送到 channel
		c.eventsChan <- event
	}
}
