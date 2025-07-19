// internal/collector/bpf/probe.c

// 唯一的 include，由 bpf2go 根据系统 BTF 自动生成
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义发送给用户空间的数据结构
struct traffic_event {
    u32 pid;
    u64 len;
};

// 使用 BPF_MAP_TYPE_PERF_EVENT_ARRAY 定义一个 perf buffer map
// 用于将事件从内核空间发送到用户空间
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// SEC("tp/net/net_dev_xmit") 将此函数附加到 net_dev_xmit tracepoint
// 当内核将一个数据包交给网络设备发送时，此 tracepoint 会被触发
SEC("tp/net/net_dev_xmit")
int handle_net_dev_xmit(struct trace_event_raw_net_dev_xmit *ctx) {
    // 创建一个事件结构体实例
    struct traffic_event event = {};

    // 获取当前进程的 PID
    // bpf_get_current_pid_tgid() 返回一个64位数，高32位是 TGID (线程组ID, 即PID)，低32位是 TID (线程ID)
    u64 id = bpf_get_current_pid_tgid();
    event.pid = id >> 32;

    // 从 tracepoint 上下文中获取数据包的长度
    event.len = (u64)ctx->len;

    // 将事件数据提交到 perf buffer
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// 许可证声明，对于 eBPF 程序是必需的
char LICENSE[] SEC("license") = "GPL";