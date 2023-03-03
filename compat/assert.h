/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ASSERT_H
#define SQUID_ASSERT_H

#if PURIFY
#define assert(EX) ((void)0)
#elif defined(NODEBUG)
#define assert(EX) ((void)0)
#else
#define assert(EX)  ((EX)?((void)0):xassert( # EX , __FILE__, __LINE__))
#endif

#ifdef __cplusplus
extern "C" void
#else
extern void
#endif
xassert(const char *, const char *, int);

#endif /* SQUID_ASSERT_H */

