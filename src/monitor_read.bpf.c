#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Estructura de evento que será enviada al espacio de usuario
struct read_event {
    __u32 pid;
    __u32 fd;
    __u64 count;
    char comm[16];
};

// Mapa tipo ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

// Programa principal eBPF: se engancha al tracepoint de sys_enter_read
SEC("tracepoint/syscalls/sys_enter_read")
int handle_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    struct read_event *e;

    // Reservar espacio en el ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // No hay espacio en buffer
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->fd = ctx->args[0];
    e->count = ctx->args[2];
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Enviar al espacio de usuario
    bpf_ringbuf_submit(e, 0);
    return 0;
}
