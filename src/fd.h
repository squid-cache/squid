/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#ifndef SQUID_FD_H_
#define SQUID_FD_H_

#include "sbuf/forward.h"

void fd_close(int fd);
void fd_open(int fd, unsigned int type, const SBuf &);
void fd_note(int fd, const SBuf &);
void fd_bytes(int fd, int len, unsigned int type);
void fdDumpOpen(void);
int fdUsageHigh(void);
void fdAdjustReserved(void);
int default_read_method(int, char *, int);
int default_write_method(int, const char *, int);

#endif /* SQUID_FD_H_ */

