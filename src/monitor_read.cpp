#include <iostream>
#include <csignal>
#include <unistd.h>

#include <linux/bpf.h>
#include <fcntl.h>
#include <map>
#include <bpf/bpf.h>      
#include <bpf/libbpf.h>
#include <fstream>
#include <string>



static volatile bool running = true;

void handle_signal(int) {
    running = false;
}

struct event {
    uint32_t pid;
    char comm[16];
    uint64_t bytes;
    char op;
};

std::map<uint32_t, uint64_t> read_stats;
std::map<uint32_t, uint64_t> write_stats;
std::map<uint32_t, std::string> proc_names;

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct event *e = (struct event *)data;
    proc_names[e->pid] = e->comm;

    if (e->op == 'R')
        read_stats[e->pid] += e->bytes;
    else if (e->op == 'W')
        write_stats[e->pid] += e->bytes;

    std::cout << "PID: " << e->pid
              << " COMM: " << e->comm
              << " OP: " << (e->op == 'R' ? "READ" : "WRITE")
              << " BYTES: " << e->bytes
              << std::endl;
}

void print_stats() {
    std::cout << "PID\tREAD_BYTES\tWRITE_BYTES\tCOMM\n";
    for (const auto& [pid, name] : proc_names) {
        std::cout << pid << "\t" << read_stats[pid]
                  << "\t\t" << write_stats[pid]
                  << "\t\t" << name << "\n";
    }
}

int main() {
    struct bpf_object *obj = nullptr;
    struct perf_buffer *pb = nullptr;
    int err;

    signal(SIGINT, handle_signal);

    obj = bpf_object__open_file("monitor_read.bpf.o", nullptr);
    if (!obj) {
        std::cerr << "Error al abrir el archivo .bpf.o\n";
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        std::cerr << "Error al cargar el objeto BPF\n";
        return 1;
    }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *sec_name = bpf_program__section_name(prog);
        if (strcmp(sec_name, "tracepoint/syscalls/sys_exit_read") == 0) {
            bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_read");
        if (strcmp(sec_name, "tracepoint/syscalls/sys_exit_writev") == 0) {
            bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_writev");
            }
        } else if (strcmp(sec_name, "tracepoint/syscalls/sys_exit_write") == 0) {
            bpf_program__attach_tracepoint(prog, "syscalls", "sys_exit_write");
        }
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        std::cerr << "No se encontró el mapa 'events'\n";
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, nullptr, nullptr, nullptr);
    if (!pb) {
        std::cerr << "Error al crear perf_buffer\n";
        return 1;
    }

    std::cout << "Escuchando eventos. Ctrl+C para salir.\n";

    while (running) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0) {
            std::cerr << "Error en perf_buffer__poll: " << err << "\n";
            break;
        }
    }

    print_stats();

    perf_buffer__free(pb);
    bpf_object__close(obj);

    return 0;
}