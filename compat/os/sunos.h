#ifndef SQUID_OS_SUNOS_H
#define SQUID_OS_SUNOS_H

#if _SQUID_SUNOS_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/* O_NONBLOCK requires <fcntl.h> to be included first */
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

/*
 * We assume O_NONBLOCK is broken, or does not exist, on SunOS.
 */
#define SQUID_NONBLOCK O_NDELAY

#endif /* _SQUID_SUNOS_ */
#endif /* SQUID_OS_SUNOS_H */
