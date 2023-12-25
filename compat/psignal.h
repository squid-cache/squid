/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef __SQUID_PSIGNAL_H
#define __SQUID_PSIGNAL_H

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

extern void psignal(int sig, const char* msg);

#endif /* __SQUID_PSIGNAL_H */

