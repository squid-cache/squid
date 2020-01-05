/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_FATAL_H
#define SQUID_FATAL_H

void fatal(const char *message);
void fatalf(const char *fmt,...) PRINTF_FORMAT_ARG1;
void fatal_dump(const char *message);

#endif /* SQUID_FATAL_H */

