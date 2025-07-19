// 文件路径: internal/collector/bpf/probe.c

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

// 定义发送给用户空间Go程序的数据结构
struct traffic_event
{
    u64 bytes;                // 字节数
    u32 pid;                  // 进程ID
    char comm[TASK_COMM_LEN]; // 进程名
    bool is_tx;               // 是否是发送流量 (true=TX, false=RX)
};

// 定义一个BPF_MAP_TYPE_PERF_EVENT_ARRAY类型的BPF映射
// 这是从内核空间向用户空间发送事件的标准方式
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// === 发送流量 (TX) 探针 ===
SEC("kprobe/net_dev_start_xmit")
int BPF_KPROBE(probe_tx, struct sk_buff *skb)
{
    // 获取当前进程的ID和名称
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // 实例化一个事件结构体
    struct traffic_event event = {};

    // 填充数据
    event.pid = pid;
    event.bytes = skb->len;
    event.is_tx = true;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 通过 perf event array 将事件发送到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// === 接收流量 (RX) 探针 ===
SEC("kprobe/netif_receive_skb")
int BPF_KPROBE(probe_rx, struct sk_buff *skb)
{
    // 获取当前进程的ID和名称
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // 实例化一个事件结构体
    struct traffic_event event = {};

    // 填充数据
    event.pid = pid;
    event.bytes = skb->len;
    event.is_tx = false; // 标记为接收
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // 发送事件
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

// BPF程序必须有一个许可证
char LICENSE[] SEC("license") = "GPL";