/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#ifndef SQUID_SRC_FD_H
#define SQUID_SRC_FD_H

/// distinguishes reading/importing I/O operations from their writing/exporting counterparts
enum class IoDirection {
    Read,
    Write
};

void fd_close(int fd);
void fd_open(int fd, unsigned int type, const char *);
void fd_note(int fd, const char *);
void fd_bytes(int fd, int len, IoDirection);
void fdDumpOpen(void);
int fdUsageHigh(void);
void fdAdjustReserved(void);
int default_read_method(int, char *, int);
int default_write_method(int, const char *, int);

#endif /* SQUID_SRC_FD_H */

