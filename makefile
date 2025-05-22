# Paths
INCLUDES := -Iinclude
SRC_DIR := src
BPF_SRC := $(SRC_DIR)/monitor_read.bpf.c
BPF_OBJ := monitor_read.bpf.o 


# Tools
CLANG := clang
CXX := g++
CXXFLAGS := -O2 -g $(INCLUDES)
BPF_CLANG_FLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(shell uname -m) -I. -I./include

# Libs
LIBS := -lbpf -lelf -lz

# Targets
all: monitor_read

monitor_read: $(SRC_DIR)/monitor_read.cpp $(BPF_OBJ)
	
	$(CXX) $(CXXFLAGS) $< -o $@ $(LIBS)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(BPF_CLANG_FLAGS) -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f monitor_read $(BPF_OBJ) vmlinux.h


correr:
	sudo mount -t bpf bpf /sys/fs/bpf
	sudo ./monitor_read