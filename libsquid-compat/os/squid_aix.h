#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_AIX_H
#define SQUID_OS_AIX_H

#ifdef _SQUID_AIX_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/


/*
 * Syslog facility on AIX requires some portability wrappers
 */
#ifdef HAVE_SYSLOG_H
#define _XOPEN_EXTENDED_SOURCE
#define _XOPEN_SOURCE_EXTENDED 1
#endif


#endif /* _SQUID_AIX_ */
#endif /* SQUID_OS_AIX_H */
