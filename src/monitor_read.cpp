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
std::ofstream csv_file;
bool csv_initialized = false;

void init_csv() {
    if (csv_initialized) return;

    time_t now = time(nullptr);
    struct tm *lt = localtime(&now);
    char filename[64];
    strftime(filename, sizeof(filename), "processed_data/eventos_log_%Y%m%d_%H%M.csv", lt);

    csv_file.open(filename);
    csv_file << "PID,COMM,OP,WBYTES,RBYTES,TIME_us,DWBytes,DRBytes\n";
    csv_initialized = true;
}

void print_process(event* e,uint64_t wbytes,uint64_t rbytes,double dw,double dr,long long us){
    init_csv();    
    std::cout << "PID: " << e->pid
              << " COMM: " << e->comm
              << " OP: " << (e->op == 'R' ? "READ" : "WRITE")
              << " BYTES: " << e->bytes
              << "    TIME us: " << us
              << std::endl;

    
    if (csv_file.is_open()) {
                csv_file << std::fixed;
    // Escribir evento en CSV
                csv_file << e->pid << ","
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

    


void process_event(void *data) {
    event *e = (event *)data;
    uint32_t pid = e->pid;

    // ---- actualizar acumulados por proceso ----
    if (!proc_stats.count(pid)) {
        proc_stats[pid].comm = e->comm;
    }

    if (e->op == 'R') {
        proc_stats[pid].read_bytes += e->bytes;
    } else if (e->op == 'W') {
        proc_stats[pid].write_bytes += e->bytes;
    }

    // ---- tiempo actual en microsegundos ----
    auto now = std::chrono::steady_clock::now();
    long long us = std::chrono::duration_cast<std::chrono::microseconds>(
                       now.time_since_epoch())
                       .count();

    // valores acumulados actuales
    uint64_t curr_w = (e->op == 'W') ? e->bytes : 0;
    uint64_t curr_r = (e->op == 'R') ? e->bytes : 0;

    double dw = 0, dr = 0;

    // ---- si NO hay datos previos, inicializar y salir ----
    if (!last_time.count(pid)) {
        last_time[pid] = us;
        last_wbytes[pid] = curr_w;
        last_rbytes[pid] = curr_r;
        print_process(e, curr_w, curr_r, dw, dr, us);
        return;
    }

    // ---- calcular derivadas ----
    long long dt = us - last_time[pid];

    if (dt > 0) {
        long long diff_w = (long long)curr_w - (long long)last_wbytes[pid];
        long long diff_r = (long long)curr_r - (long long)last_rbytes[pid];

        dw = double(diff_w) / double(dt);
        dr = (double)(diff_r) / double(dt);
    }

    // ---- actualizar estado previo ----
    last_time[pid] = us;
    last_wbytes[pid] = curr_w;
    last_rbytes[pid] = curr_r;

    // ---- imprimir con valores correctos ----
    print_process(e, curr_w, curr_r, dw, dr, us);
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