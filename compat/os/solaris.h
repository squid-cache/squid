#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_SOLARIS_H
#define SQUID_OS_SOLARIS_H

#ifdef _SQUID_SOLARIS_

/*
 * On Solaris 9 x86, gcc may includes a "fixed" set of old system
 * include files that is incompatible with the updated Solaris
 * header files.
 */
#if defined(i386) || defined(__i386)
#ifndef HAVE_PAD128_T
typedef union {
    long double	_q;
    int32_t		_l[4];
} pad128_t;
#endif
#ifndef HAVE_UPAD128_T
typedef union {
    long double	_q;
    uint32_t	_l[4];
} upad128_t;
#endif
#endif

/**
 * prototypes for system function missing from system includes
 */
#include <sys/resource.h>
SQUIDCEXTERN int getrusage(int, struct rusage *);


/**
 * prototypes for system function missing from system includes
 * on some Solaris systems.
 */
SQUIDCEXTERN int getpagesize(void);
#if !defined(_XPG4_2) && !(defined(__EXTENSIONS__) || \
(!defined(_POSIX_C_SOURCE) && !defined(_XOPEN_SOURCE)))
SQUIDCEXTERN int gethostname(char *, int);
#endif



#endif /* _SQUID_SOLARIS_ */
#endif /* SQUID_OS_SOALRIS_H */
