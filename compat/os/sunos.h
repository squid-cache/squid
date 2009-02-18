#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_SUNOS_H
#define SQUID_OS_SUNOS_H

#ifdef _SQUID_SUNOS_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/


/*
 * We assume O_NONBLOCK is broken, or does not exist, on SunOS.
 */
#define SQUID_NONBLOCK O_NDELAY



#endif /* _SQUID_SUNOS_ */
#endif /* SQUID_OS_SUNOS_H */
