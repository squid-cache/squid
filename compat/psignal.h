/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_COMPAT_PSIGNAL_H
#define SQUID_COMPAT_PSIGNAL_H

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

extern void psignal(int sig, const char* msg);

#endif /* SQUID_COMPAT_PSIGNAL_H */

