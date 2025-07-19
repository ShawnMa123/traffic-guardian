// internal/state/manager.go
package state

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"traffic-guardian/internal/collector"
	"traffic-guardian/internal/config"
)

// ProcessStats 存储单个进程的流量信息
type ProcessStats struct {
	PID        uint32
	TotalBytes uint64
	LastSeen   time.Time
}

// Manager 负责管理所有进程的流量状态
type Manager struct {
	log           *slog.Logger
	trafficStates map[uint32]*ProcessStats
	mu            sync.RWMutex
	timeWindow    time.Duration
}

// NewManager 创建一个新的状态管理器
func NewManager(log *slog.Logger, cfg *config.Config) *Manager {
	return &Manager{
		log:           log,
		trafficStates: make(map[uint32]*ProcessStats),
		timeWindow:    cfg.Rules.GetTimeWindow(),
	}
}

// Start 启动状态管理器的主循环
func (m *Manager) Start(ctx context.Context, eventsChan <-chan collector.TrafficEvent) {
	m.log.Info("Starting state manager")
	// 创建一个定时器来定期清理过期的数据
	ticker := time.NewTicker(m.timeWindow)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.log.Info("State manager stopped")
			return
		case event := <-eventsChan:
			m.updateState(event)
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// updateState 更新一个进程的流量数据
func (m *Manager) updateState(event collector.TrafficEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.trafficStates[event.PID]
	if !ok {
		stats = &ProcessStats{PID: event.PID}
		m.trafficStates[event.PID] = stats
	}

	stats.TotalBytes += event.Len
	stats.LastSeen = time.Now()
}

// cleanup 删除在时间窗口内没有活动的老数据
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	cleanedCount := 0
	for pid, stats := range m.trafficStates {
		if now.Sub(stats.LastSeen) > m.timeWindow {
			delete(m.trafficStates, pid)
			cleanedCount++
		}
	}
	if cleanedCount > 0 {
		m.log.Debug("Cleaned up old state entries", "count", cleanedCount)
	}
}

// GetStats 返回当前所有流量状态的一个副本，保证线程安全
func (m *Manager) GetStats() []ProcessStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	statsCopy := make([]ProcessStats, 0, len(m.trafficStates))
	for _, stats := range m.trafficStates {
		statsCopy = append(statsCopy, *stats)
	}
	return statsCopy
}
