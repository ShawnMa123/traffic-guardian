// internal/alerter/telegram.go
package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"traffic-guardian/internal/config"
	"traffic-guardian/internal/state"
)

// Alert 定义了警报事件的数据结构
type Alert struct {
	ProcessStats state.ProcessStats
	Timestamp    time.Time
}

// Alerter 是所有警报器都需要实现的接口
type Alerter interface {
	Send(ctx context.Context, alert Alert) error
	IsEnabled() bool
}

// TelegramAlerter 通过 Telegram Bot 发送警报
type TelegramAlerter struct {
	log    *slog.Logger
	cfg    config.TelegramConfig
	client *http.Client
}

// NewTelegramAlerter 创建一个新的 TelegramAlerter 实例
func NewTelegramAlerter(log *slog.Logger, cfg config.TelegramConfig) *TelegramAlerter {
	return &TelegramAlerter{
		log:    log,
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// IsEnabled 检查此警报器是否被启用
func (t *TelegramAlerter) IsEnabled() bool {
	return t.cfg.Enabled
}

// Send 实现了 Alerter 接口的 Send 方法
func (t *TelegramAlerter) Send(ctx context.Context, alert Alert) error {
	t.log.Info("Sending alert to Telegram", "pid", alert.ProcessStats.PID)

	// 格式化消息内容
	message := fmt.Sprintf(
		"🚨 **Traffic Alert** 🚨\n\n"+
			"**Process ID:** `%d`\n"+
			"**Traffic Used:** `%.2f MB`\n"+
			"**Time:** `%s`\n\n"+
			"The process has exceeded the configured traffic limit.",
		alert.ProcessStats.PID,
		float64(alert.ProcessStats.TotalBytes)/(1024*1024),
		alert.Timestamp.Format(time.RFC1123),
	)

	// 构建 API 请求
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", t.cfg.BotToken)
	payload := map[string]string{
		"chat_id":    t.cfg.ChatID,
		"text":       message,
		"parse_mode": "Markdown",
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal telegram payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// 发送请求
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send telegram message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned non-200 status: %s", resp.Status)
	}

	t.log.Info("Alert sent successfully", "pid", alert.ProcessStats.PID)
	return nil
}
