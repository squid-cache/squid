#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_FREEBSD_H
#define SQUID_OS_FREEBSD_H

#ifdef _SQUID_FREEBSD_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/


#if USE_ASYNC_IO && defined(LINUXTHREADS)
#define _SQUID_LINUX_THREADS_
#endif

/*
 * Don't allow inclusion of malloc.h
 */
#if defined(HAVE_MALLOC_H)
#undef HAVE_MALLOC_H
#endif

#define _etext etext

#endif /* _SQUID_FREEBSD_ */
#endif /* SQUID_OS_FREEBSD_H */
