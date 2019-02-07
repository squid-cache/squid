/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 02    Unlink Daemon */

#ifndef SQUID_UNLINKD_H_
#define SQUID_UNLINKD_H_

#if USE_UNLINKD
bool unlinkdNeeded(void);
void unlinkdInit(void);
void unlinkdClose(void);
void unlinkdUnlink(const char *);
#else /* USE_UNLINKD */

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
inline bool unlinkdNeeded(void) { return false; }
inline void unlinkdInit(void) { return; }
inline void unlinkdClose(void) { return; }
inline void unlinkdUnlink(const char * path) { ::unlink(path); }
#endif /* USE_UNLINKD */

#endif /* SQUID_UNLINKD_H_ */

