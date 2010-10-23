#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef _SQUID_COMPAT_SHARED_H
#define _SQUID_COMPAT_SHARED_H

/*
 * This file contains all the compatibility and portability hacks
 * Which are general-case and shared between all OS and support programs.
 *
 * If an OS-specific hack is needed there are per-OS files for that in
 * the os/ sub-directory here.
 *
 * These hacks should be platform and location agnostic.
 * A quick look-over of the code already here should give you an idea
 * of the requirements for wrapping your hack for safe portability.
 */


/*
 * sys/resource.h and sys/time.h are apparently order-dependant.
 */
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>       /* needs sys/time.h above it */
#endif

/*
 * DIRENT functionality can apparently come from many places.
 * I believe these should really be done by OS-specific compat
 * files, but for now its left here.
 */
#if HAVE_DIRENT_H
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)

#else /* if not HAVE_DIRENT_H */
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen
#if HAVE_SYS_NDIR_H
#include <sys/ndir.h>
#endif /* HAVE_SYS_NDIR_H */
#if HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif /* HAVE_SYS_DIR_H */
#if HAVE_NDIR_H
#include <ndir.h>
#endif /* HAVE_NDIR_H */
#endif /* HAVE_DIRENT_H */


/*
 * Filedescriptor limits in the different select loops
 *
 * NP: FreeBSD 7 defines FD_SETSIZE as unsigned but Squid needs
 *     it to be signed to compare it with signed values.
 *     Linux and others including FreeBSD <7, define it as signed.
 *     If this causes any issues please contact squid-dev@squid-cache.org
 */
#if defined(USE_SELECT) || defined(USE_SELECT_WIN32)
/* Limited by design */
# define SQUID_MAXFD_LIMIT    ((signed int)FD_SETSIZE)

#elif defined(USE_POLL)
/* Limited due to delay pools */
# define SQUID_MAXFD_LIMIT    ((signed int)FD_SETSIZE)

#elif defined(USE_KQUEUE) || defined(USE_EPOLL) || defined(USE_DEVPOLL)
# define SQUID_FDSET_NOUSE 1

#else
# error Unknown select loop model!
#endif



#if !HAVE_STRUCT_RUSAGE
/**
 * If we don't have getrusage() then we create a fake structure
 * with only the fields Squid cares about.  This just makes the
 * source code cleaner, so we don't need lots of ifdefs in other
 * places
 */
struct rusage {
    struct timeval ru_stime;
    struct timeval ru_utime;
    int ru_maxrss;
    int ru_majflt;
};
#endif /* !HAVE_STRUCT_RUSAGE */


#ifndef min
#ifdef __cplusplus
/**
 * min() comparison may not always be provided.
 * Squid bundles this template for when its needed.
 * May be used on any type which provides operator '<'
 */
template<class A>
inline A const &
min(A const & lhs, A const & rhs)
{
    if (rhs < lhs)
        return rhs;
    return lhs;
}
#else /* !__cplusplus */
/* for non-C++ we are stuck with the < and ? operator */
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif /* __cplusplus */
#endif /* min */

#ifndef max
#ifdef __cplusplus
/**
 * max() comparison may not always be provided.
 * Squid bundles this template for when its needed.
 * May be used on any type which provides operator '>'
 */
template<class A>
inline A const &
max(A const & lhs, A const & rhs)
{
    if (rhs > lhs)
        return rhs;
    return lhs;
}
#else /* !__cplusplus */
/* for non-C++ we are stuck with the < and ? operator */
#define max(a,b) ((a) < (b) ? (b) : (a))
#endif /* __cplusplus */
#endif /* max */

/**
 * tempnam() not provided by all systems
 * TODO: detect WHICH systems and move to their OS-specific compat files
 */
#if !HAVE_TEMPNAM
#include "tempnam.h"
#endif

/**
 * strsep() not provided by all systems
 * TODO: detect WHICH systems and move to their OS-specific compat files
 */
#if !HAVE_STRSEP
#include "strsep.h"
#endif

/**
 * strtoll() not provided by all systems
 * TODO: detect WHICH systems and move to their OS-specific compat files
 */
#if !HAVE_STRTOLL
#include "strtoll.h"
#endif

/**
 * Common shared definition of what whitespace consists of for string tests
 */
#define w_space     " \t\n\r"

/**
 * initgroups() not provided by all systems
 * TODO: detect WHICH systems and move to their OS-specific compat files
 */
#if !HAVE_INITGROUPS
#include "initgroups.h"
#endif


/* REQUIRED for the below logics. If they move this needs to as well */
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if defined(O_NONBLOCK)
/**
 * We used to assume O_NONBLOCK was broken on Solaris, but evidence
 * now indicates that its fine on Solaris 8, and in fact required for
 * properly detecting EOF on FIFOs.  So now we assume that if
 * its defined, it works correctly on all operating systems.
 */
#define SQUID_NONBLOCK O_NONBLOCK
#else
/** O_NDELAY is our fallback. */
#define SQUID_NONBLOCK O_NDELAY
#endif


/**
 * Signalling flags are apparently not always provided.
 * TODO find out if these can be moved into specific OS portability files.
 */
#ifndef SA_RESTART
#define SA_RESTART 0
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif
#ifndef SA_RESETHAND
#define SA_RESETHAND 0
#endif
#if SA_RESETHAND == 0 && defined(SA_ONESHOT)
#undef SA_RESETHAND
#define SA_RESETHAND SA_ONESHOT
#endif


#endif /* _SQUID_COMPAT_SHARED_H */
