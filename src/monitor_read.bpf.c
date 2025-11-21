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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");


SEC("tracepoint/syscalls/sys_exit_read")
int handle_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct event data = {};
    data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_target(data.comm))
        return 0;

    data.bytes = (u64)ret;
    data.op = 'R';

    void *buf = bpf_ringbuf_reserve(&events, sizeof(data), 0);
    if (!buf)
        return 0;
    __builtin_memcpy(buf, &data, sizeof(data));
    bpf_ringbuf_submit(buf, 0);

    return 0;
}


SEC("tracepoint/syscalls/sys_exit_write")
int handle_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    s64 ret = ctx->ret;
    if (ret <= 0)
        return 0;

    struct event data = {};
    data.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    if (!is_target(data.comm))
        return 0;

    data.bytes = (u64)ret;
    data.op = 'W';

    void *buf = bpf_ringbuf_reserve(&events, sizeof(data), 0);
    if (!buf)
        return 0;
    __builtin_memcpy(buf, &data, sizeof(data));
    bpf_ringbuf_submit(buf, 0);

    return 0;
}