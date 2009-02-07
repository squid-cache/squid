#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_OPENBSD_H
#define SQUID_OS_OPENBSD_H

#ifdef _SQUID_OPENBSD_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

/*
 * Don't allow inclusion of malloc.h
 */
#ifdef HAVE_MALLOC_H
#undef HAVE_MALLOC_H
#endif


#endif /* _SQUID_OPENBSD_ */
#endif /* SQUID_OS_OPENBSD_H */
