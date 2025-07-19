// cmd/traffic-guardian/main.go
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"traffic-guardian/internal/alerter"
	"traffic-guardian/internal/collector"
	"traffic-guardian/internal/config"
	"traffic-guardian/internal/engine"
	"traffic-guardian/internal/state"
)

func main() {
	// 1. 初始化
	// 解析命令行参数
	configFile := flag.String("config", "config.yaml", "Path to the configuration file")
	flag.Parse()

	// 加载配置
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// 设置结构化日志
	logLevel := new(slog.LevelVar)
	switch cfg.LogLevel {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "warn":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// 设置优雅退出的上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 使用 WaitGroup 等待所有 goroutine 退出
	var wg sync.WaitGroup

	// 2. 创建组件
	// 创建用于数据流转的 channels
	trafficEventsChan := make(chan collector.TrafficEvent, 100)
	alertsChan := make(chan alerter.Alert, 10)

	// 创建状态管理器
	stateManager := state.NewManager(logger.With("module", "state"), cfg)

	// 创建规则引擎
	ruleEngine := engine.NewEngine(logger.With("module", "engine"), cfg, stateManager, alertsChan)

	// 创建并注册警报器
	var alerters []alerter.Alerter
	telegramAlerter := alerter.NewTelegramAlerter(logger.With("module", "alerter-telegram"), cfg.Alerter.Telegram)
	if telegramAlerter.IsEnabled() {
		slog.Info("Telegram alerter is enabled")
		alerters = append(alerters, telegramAlerter)
	} else {
		slog.Info("Telegram alerter is disabled")
	}

	// 创建 eBPF 采集器
	bpfCollector := collector.New(logger.With("module", "collector"), trafficEventsChan)

	// 3. 启动所有组件（作为 Goroutines）
	wg.Add(4)

	// 启动状态管理器
	go func() {
		defer wg.Done()
		stateManager.Start(ctx, trafficEventsChan)
	}()

	// 启动规则引擎
	go func() {
		defer wg.Done()
		ruleEngine.Start(ctx)
	}()

	// 启动警报处理器
	go func() {
		defer wg.Done()
		slog.Info("Starting alert processor")
		for {
			select {
			case <-ctx.Done():
				slog.Info("Alert processor stopped")
				return
			case alert := <-alertsChan:
				for _, a := range alerters {
					if err := a.Send(ctx, alert); err != nil {
						slog.Error("Failed to send alert", "alerter", a, "error", err)
					}
				}
			}
		}
	}()

	// 启动 eBPF 采集器
	go func() {
		defer wg.Done()
		if err := bpfCollector.Start(ctx); err != nil {
			slog.Error("Failed to start eBPF collector", "error", err)
			cancel() // 如果采集器启动失败，则取消所有操作
		}
	}()

	// 4. 等待退出信号
	slog.Info("Traffic Guardian is running. Press Ctrl+C to exit.")
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-termChan:
		slog.Info("Shutdown signal received, gracefully shutting down...")
	case <-ctx.Done():
		slog.Warn("Context cancelled, possibly due to a startup error.")
	}

	// 触发所有 goroutine 的退出
	cancel()

	// 等待所有 goroutine 完成清理工作
	slog.Info("Waiting for all services to stop...")
	wg.Wait()
	slog.Info("Shutdown complete.")
}
