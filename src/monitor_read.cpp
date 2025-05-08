#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>
#include <event.h>
extern "C" {
    #include <bpf/libbpf.h>
    #include <bpf/bpf.h>
    #include <unistd.h>
}

static bool running = true;

void handle_signal(int) {
    running = false;
}



int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(read_event)) {
        std::cerr << "Tamaño de evento inesperado." << std::endl;
        return 0;
    }

    const read_event *e = static_cast<const read_event *>(data);

    // Filtrar solo si el proceso se llama guardarArchivo
    if (std::string(e->comm) == "guardarArchivo") {
        std::cout << "PID: " << e->pid
                  << " FD: " << e->fd
                  << " Count: " << e->count
                  << " Comm: " << e->comm << std::endl;
    }

    return 0;
}

int main() {
    struct bpf_object *obj = nullptr;
    struct ring_buffer *rb = nullptr;
    int err;

    signal(SIGINT, handle_signal);

    // 1. Abrir objeto eBPF
    obj = bpf_object__open_file("monitor_read.bpf.o", nullptr);
    if (!obj) {
        std::cerr << "Error al abrir el archivo .bpf.o" << std::endl;
        return 1;
    }

    // 2. Cargar programas y mapas
    err = bpf_object__load(obj);
    if (err) {
        std::cerr << "Error al cargar el objeto BPF" << std::endl;
        return 1;
    }

    // 3. Buscar programa eBPF por nombre
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_sys_enter_read");
    if (!prog) {
        std::cerr << "No se encontró el programa BPF" << std::endl;
        return 1;
    }

    // 4. Adjuntar al tracepoint automáticamente
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        std::cerr << "Error al adjuntar el programa" << std::endl;
        return 1;
    }

    // 5. Obtener el fd del mapa ringbuf
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        std::cerr << "No se encontró el mapa 'events'" << std::endl;
        return 1;
    }

    // 6. Configurar el ring buffer
    rb = ring_buffer__new(map_fd, handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Error al crear ring_buffer" << std::endl;
        return 1;
    }

    std::cout << "Escuchando eventos. Ctrl+C para salir." << std::endl;

    // 7. Loop principal
    while (running) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err < 0) {
            std::cerr << "Error en ring_buffer__poll: " << err << std::endl;
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    std::cout << "Programa terminado." << std::endl;
    return 0;
}
