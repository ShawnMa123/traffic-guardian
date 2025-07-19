// internal/engine/engine.go
package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"traffic-guardian/internal/alerter"
	"traffic-guardian/internal/config"
	"traffic-guardian/internal/state"
)

// Engine 负责将流量状态与规则进行比较并触发警报
type Engine struct {
	log             *slog.Logger
	stateManager    *state.Manager
	rules           config.Rules
	alertChan       chan<- alerter.Alert
	recentlyAlerted map[uint32]time.Time
	mu              sync.Mutex
	alertCooldown   time.Duration
}

// NewEngine 创建一个新的规则引擎
func NewEngine(log *slog.Logger, cfg *config.Config, stateManager *state.Manager, alertChan chan<- alerter.Alert) *Engine {
	return &Engine{
		log:             log,
		stateManager:    stateManager,
		rules:           cfg.Rules,
		alertChan:       alertChan,
		recentlyAlerted: make(map[uint32]time.Time),
		alertCooldown:   cfg.Rules.GetAlertCooldown(),
	}
}

// Start 启动规则引擎的检查循环
func (e *Engine) Start(ctx context.Context) {
	e.log.Info("Starting rule engine")
	ticker := time.NewTicker(e.rules.GetCheckInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.log.Info("Rule engine stopped")
			return
		case <-ticker.C:
			e.checkRules()
		}
	}
}

// checkRules 获取最新状态并与规则进行比较
func (e *Engine) checkRules() {
	stats := e.stateManager.GetStats()
	if len(stats) == 0 {
		return
	}

	e.log.Debug("Checking rules", "process_count", len(stats))

	threshold := e.rules.GetTrafficThresholdBytes()

	for _, s := range stats {
		if s.TotalBytes > threshold {
			if !e.isRecentlyAlerted(s.PID) {
				e.log.Warn("Rule violated", "pid", s.PID, "traffic_bytes", s.TotalBytes, "threshold_bytes", threshold)

				// 发送警报到警报 channel
				e.alertChan <- alerter.Alert{
					ProcessStats: s,
					Timestamp:    time.Now(),
				}

				// 标记此进程为已警报
				e.markAsAlerted(s.PID)
			}
		}
	}
}

// isRecentlyAlerted 检查一个进程是否在冷却期内
func (e *Engine) isRecentlyAlerted(pid uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	lastAlertTime, ok := e.recentlyAlerted[pid]
	if !ok {
		return false
	}

	if time.Since(lastAlertTime) > e.alertCooldown {
		// 冷却期已过，可以再次报警
		delete(e.recentlyAlerted, pid)
		return false
	}

	return true
}

// markAsAlerted 记录一个进程的警报时间
func (e *Engine) markAsAlerted(pid uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recentlyAlerted[pid] = time.Now()
}
