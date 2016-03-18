/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CONFIG_H
#define SQUID_CONFIG_H

#include "autoconf.h"       /* For GNU autoconf variables */

#if !defined(HAVE_SQUID)
/* sub-packages define their own version details */
#include "version.h"

#endif

/* default values for listen ports. Usually specified in squid.conf really */
#define CACHE_HTTP_PORT 3128
#define CACHE_ICP_PORT 3130

/* To keep API definitions clear */
#ifdef __cplusplus
#define SQUIDCEXTERN extern "C"
#else
#define SQUIDCEXTERN extern
#endif

#if _USE_INLINE_
#define _SQUID_INLINE_ inline
#else
#define _SQUID_INLINE_
#endif

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#include "compat/compat.h"

#ifdef USE_POSIX_REGEX
#ifndef USE_RE_SYNTAX
#define USE_RE_SYNTAX   REG_EXTENDED    /* default Syntax */
#endif
#endif

#if !defined(CACHEMGR_HOSTNAME)
#define CACHEMGR_HOSTNAME ""
#else
#define CACHEMGR_HOSTNAME_DEFINED 1
#endif

#if SQUID_DETECT_UDP_SO_SNDBUF > 16384
#define SQUID_UDP_SO_SNDBUF 16384
#else
#define SQUID_UDP_SO_SNDBUF SQUID_DETECT_UDP_SO_SNDBUF
#endif

#if SQUID_DETECT_UDP_SO_RCVBUF > 16384
#define SQUID_UDP_SO_RCVBUF 16384
#else
#define SQUID_UDP_SO_RCVBUF SQUID_DETECT_UDP_SO_RCVBUF
#endif

/*
 * Determine if this is a leak check build or standard
 */
#if PURIFY || WITH_VALGRIND
#define LEAK_CHECK_MODE 1
#endif

/* temp hack: needs to be pre-defined for now. */
#define SQUID_MAXPATHLEN 256

// TODO: determine if this is required. OR if compat/os/mswindows.h works
#if _SQUID_WINDOWS_ && defined(__cplusplus)
/** \cond AUTODOCS-IGNORE */
using namespace Squid;
/** \endcond */
#endif

// temporary for the definition of LOCAL_ARRAY
#include "leakcheck.h"

#endif /* SQUID_CONFIG_H */

