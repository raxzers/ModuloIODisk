#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __inline int is_target(const char *comm) {
    return (__builtin_memcmp(comm, "crearArchivo", 13) == 0 ||
            __builtin_memcmp(comm, "guardarArchivo", 14) == 0);
}

struct event {
    u32 pid;
    char comm[16];
    u64 bytes;
    char op; // 'R' para read, 'W' para write
};


struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");




struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} read_bytes SEC(".maps");



SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct event data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_target(data.comm))  {
        return 0;}
    data.bytes = ret;
    data.op = 'R';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}


SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct event data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_target(data.comm))  {
        return 0;}
    
    data.bytes = ret;
    data.op = 'W';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
// Manejo de sys_exit_writev
SEC("tracepoint/syscalls/sys_exit_writev")
int handle_sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct event data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_target(data.comm))  {
        return 0;}
    data.bytes = ret;
    data.op = 'W';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}