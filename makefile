# =========================
#  Configuración general
# =========================
CLANG ?= clang
CXX   ?= g++
LIBBPF_DIR ?= /usr/lib/bpf

CFLAGS = -O2 -g -Wall -m64 -I$(LIBBPF_DIR)/include -I./include -I./src
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(shell uname -m) \
	      -I. -I./include -I$(LIBBPF_DIR)/include

BUILD_DIR := build
SRC_DIR   := src
PROC_DIR  := processed_data

BPF_SRC    := $(SRC_DIR)/monitor_read.bpf.c
BPF_OBJ    := $(BUILD_DIR)/monitor_read.bpf.o
USER_OBJ   := $(BUILD_DIR)/monitor_read

VMLINUX_H  := $(SRC_DIR)/vmlinux.h
SKEL_HDR   := $(SRC_DIR)/monitor_read.skel.h

LIBS := -lbpf -lelf -lz

# =========================
#  Target principal
# =========================
all: $(USER_OBJ)

# =========================
#  Directorios requeridos
# =========================
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	mkdir -p $(PROC_DIR)

# =========================
#  Generar vmlinux.h
# =========================
$(VMLINUX_H): | $(BUILD_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# =========================
#  Compilar el BPF
# =========================
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# =========================
#  Generar skeleton
# =========================
$(SKEL_HDR): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# =========================
#  Compilar user space
# =========================
$(USER_OBJ): $(SRC_DIR)/monitor_read.cpp $(SKEL_HDR) | $(BUILD_DIR)
	$(CXX) $(CFLAGS) -o $@ $< $(LIBS)

# =========================
#  Limpiar
# =========================
clean:
	rm -rf $(BUILD_DIR)
	rm -f  $(SRC_DIR)/*.skel.h $(SRC_DIR)/vmlinux.h

# =========================
#  Ejecutar
# =========================
run:
	sudo ./build/monitor_read
