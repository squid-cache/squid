#ifndef SQUID_COMM_COMM_INTERNAL_H
#define SQUID_COMM_COMM_INTERNAL_H

/* misc collection of bits shared by Comm code, but not needed by the rest of Squid. */

struct _fd_debug_t {
    char const *close_file;
    int close_line;
};

typedef struct _fd_debug_t fd_debug_t;
extern fd_debug_t *fdd_table;

bool isOpen(const int fd);

#endif
