#ifndef EVENT_H
#define EVENT_H


struct event {
    uint32_t pid;
    char comm[16];
    uint64_t bytes;
    char op; // 'R' para read, 'W' para write
};

#endif // EVENT_H