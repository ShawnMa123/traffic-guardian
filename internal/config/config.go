// internal/config/config.go
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 结构体完整地映射了 config.yaml 文件的结构
type Config struct {
	LogLevel string  `yaml:"log_level"`
	Rules    Rules   `yaml:"rules"`
	Alerter  Alerter `yaml:"alerter"`
}

// Rules 定义了流量监控和警报的规则
type Rules struct {
	TrafficThresholdMB   int `yaml:"traffic_threshold_mb"`
	TimeWindowMinutes    int `yaml:"time_window_minutes"`
	CheckIntervalSeconds int `yaml:"check_interval_seconds"`
	AlertCooldownMinutes int `yaml:"alert_cooldown_minutes"`
}

// Alerter 定义了所有可能的警报渠道
type Alerter struct {
	Telegram TelegramConfig `yaml:"telegram"`
}

// TelegramConfig 定义了 Telegram 警报器的具体配置
type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

// LoadConfig 从指定路径读取并解析 YAML 配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}

// GetTrafficThresholdBytes 是一个辅助函数，将MB转换为Bytes
func (r *Rules) GetTrafficThresholdBytes() uint64 {
	return uint64(r.TrafficThresholdMB) * 1024 * 1024
}

// GetTimeWindow 是一个辅助函数，将分钟转换为 time.Duration
func (r *Rules) GetTimeWindow() time.Duration {
	return time.Duration(r.TimeWindowMinutes) * time.Minute
}

// GetCheckInterval 是一个辅助函数，将秒转换为 time.Duration
func (r *Rules) GetCheckInterval() time.Duration {
	return time.Duration(r.CheckIntervalSeconds) * time.Second
}

// GetAlertCooldown 是一个辅助函数，将分钟转换为 time.Duration
func (r *Rules) GetAlertCooldown() time.Duration {
	return time.Duration(r.AlertCooldownMinutes) * time.Minute
}
