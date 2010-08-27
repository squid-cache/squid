#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_SOLARIS_H
#define SQUID_OS_SOLARIS_H


#if _SQUID_SOLARIS_


/*
 * ugly hack. System headers require wcsstr, but don't define it.
 */
#include <wchar.h>
#ifdef wcsstr
#undef wcsstr
#endif /* wcsstr */
#define wcsstr wcswcs

/*
 * On Solaris 9 x86, gcc may includes a "fixed" set of old system
 * include files that is incompatible with the updated Solaris
 * header files.
 */
#if defined(i386) || defined(__i386)
#if !HAVE_PAD128_T
typedef union {
    long double	_q;
    int32_t		_l[4];
} pad128_t;
#endif
#if !HAVE_UPAD128_T
typedef union {
    long double	_q;
    uint32_t	_l[4];
} upad128_t;
#endif
#endif

/**
 * prototypes for system function missing from system includes
 * NP: sys/resource.h and sys/time.h are apparently order-dependant.
 */
#include <sys/time.h>
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

/*
 * SunPro CC handles extern inline as inline, PLUS extern symbols.
 */
#if !defined(_SQUID_EXTERNNEW_) && defined(__SUNPRO_CC)
#define _SQUID_EXTERNNEW_ extern
#endif

/*
 * SunStudio CC does not define C++ portability API __FUNCTION__
 */
#if defined(__SUNPRO_CC) && !defined(__FUNCTION__)
#define __FUNCTION__ ""
#endif

/* Exclude CPPUnit tests from the allocator restrictions. */
/* BSD implementation uses these still */
#if defined(SQUID_UNIT_TEST)
#define SQUID_NO_STRING_BUFFER_PROTECT 1
#endif

/* Bug 2500: Solaris 10/11 require s6_addr* defines. */
//#define s6_addr8   _S6_un._S6_u8
//#define s6_addr16  _S6_un._S6_u16
#define s6_addr32  _S6_un._S6_u32


#endif /* _SQUID_SOLARIS_ */
#endif /* SQUID_OS_SOALRIS_H */
