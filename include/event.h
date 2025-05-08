#ifndef EVENT_H
#define EVENT_H

#include <cstdint>

struct read_event {
    uint32_t pid;
    uint32_t fd;
    uint64_t count;
    char comm[16];
};

#endif // EVENT_H