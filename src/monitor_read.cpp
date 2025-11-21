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
#include <vector>
#include <chrono>
#include <iomanip>
#include <ctime>
#include "monitor_read.skel.h"

static volatile bool running = true;

void handle_signal(int) {
    running = false;
}

struct Stats {
    std::string comm;
    uint64_t read_bytes = 0;
    uint64_t write_bytes = 0;
};

struct event {
    uint32_t pid;
    char comm[16];
    uint64_t bytes;
    char op;
};

std::map<pid_t, uint64_t> write_stats;
std::map<pid_t, uint64_t> read_stats;
std::map<pid_t, uint64_t> last_wbytes;
std::map<pid_t, uint64_t> last_rbytes;
std::map<pid_t, long long> last_time;


std::map<uint32_t, Stats> proc_stats;
std::map<uint32_t, std::string> proc_names;

void process_event(void *data) {
    struct event *e = (struct event *)data;
    uint32_t pid = e->pid;

    // Guardar stats en memoria
    if (proc_stats.find(pid) == proc_stats.end()) {
        proc_stats[pid].comm = e->comm;
    }

    if (e->op == 'R') {
        proc_stats[pid].read_bytes += e->bytes;
    } else if (e->op == 'W') {
        proc_stats[pid].write_bytes += e->bytes;
    }

    // Obtener tiempo actual en microsegundos
    auto now = std::chrono::system_clock::now();
    auto epoch = now.time_since_epoch();
    long long us = std::chrono::duration_cast<std::chrono::microseconds>(epoch).count();

    std::cout << "PID: " << e->pid
              << " COMM: " << e->comm
              << " OP: " << (e->op == 'R' ? "READ" : "WRITE")
              << " BYTES: " << e->bytes
              << "    TIME us: " << us
              << std::endl;

    std::ofstream out("processed_data/eventos_log.csv", std::ios::app);
    if (out) {
    static bool encabezado_escrito = false;
    if (!encabezado_escrito && out.tellp() == 0) {
        out << "PID,COMM,OP,WBYTES,RBYTES,TIME_us,DWBytes,DRBytes\n";
        encabezado_escrito = true;
    }

    // Determinar WBYTES/RBYTES por operación
    uint64_t wbytes = (e->op == 'W') ? e->bytes : 0;
    uint64_t rbytes = (e->op == 'R') ? e->bytes : 0;

    // Calcular derivadas
    double dw = 0, dr = 0;
    if (last_time.find(e->pid) != last_time.end()) {
        long long delta_t = us - last_time[e->pid];
        if (delta_t > 0) {
            dw = static_cast<double>(wbytes + write_stats[e->pid] - last_wbytes[e->pid]) / delta_t;
            dr = static_cast<double>(rbytes + read_stats[e->pid] - last_rbytes[e->pid]) / delta_t;
        }
    }

    // Actualizar estado previo
    last_wbytes[e->pid] = write_stats[e->pid] + wbytes;
    last_rbytes[e->pid] = read_stats[e->pid] + rbytes;
    last_time[e->pid] = us;

    // Escribir evento en CSV
    out << e->pid << ","
        << e->comm << ","
        << (e->op == 'R' ? "READ" : "WRITE") << ","
        << wbytes << ","
        << rbytes << ","
        << us << ","
        << dw << ","
        << dr
        << "\n";
}
}

void print_stats() {
    std::cout << "\n=== RESUMEN FINAL ===\n";
    for (const auto& [pid, stat] : proc_stats) {
    std::cout << "PID: " << pid
              << " COMM: " << stat.comm
              << " READ_BYTES: " << stat.read_bytes
              << " WRITE_BYTES: " << stat.write_bytes
              << std::endl;
}
}

int main() {

    struct ring_buffer *rb = nullptr;
    int err;

    struct monitor_read_bpf *skel = monitor_read_bpf__open_and_load();
    if (!skel) {
        std::cerr << "Failed to open/load skeleton\n";
        return 1;
    }

    if (monitor_read_bpf__attach(skel)) {
        std::cerr << "Failed to attach probes\n";
        monitor_read_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, handle_signal);

    // Obtener FD del mapa ringbuf
    int map_fd = bpf_map__fd(skel->maps.events);
    if (map_fd < 0) {
        std::cerr << "No se encontró el mapa 'events'\n";
        return 1;
    }

    auto handle_event = [](void *ctx, void *data, size_t size) {
        

            process_event(data);
        
        return 0;
    };

    // Crear ring buffer
    rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Error al crear ring_buffer\n";
        return 1;
    }

    std::cout << "Escuchando eventos con ring_buffer. Ctrl+C para salir.\n";

    while (running) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            //std::cerr << "Error en ring_buffer__poll: " << err << "\n";
            break;
        }
        // err >= 0 significa OK (cantidad de eventos procesados)
    }

    print_stats();

    ring_buffer__free(rb);
    //bpf_object__close(obj);
    monitor_read_bpf__destroy(skel);
    return 0;
}