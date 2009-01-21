#ifndef SQUID_CONFIG_H
#include "config.h"
#endif

#ifndef SQUID_OS_SGI_H
#define SQUID_OS_SGI_H

#if _SQUID_SGI_

/****************************************************************************
 *--------------------------------------------------------------------------*
 * DO *NOT* MAKE ANY CHANGES below here unless you know what you're doing...*
 *--------------------------------------------------------------------------*
 ****************************************************************************/

#if !defined(_SVR4_SOURCE)
#define _SVR4_SOURCE		/* for tempnam(3) */
#endif

#if USE_ASYNC_IO
#define _ABI_SOURCE
#endif /* USE_ASYNC_IO */


#endif /* _SQUID_SGI_ */
#endif /* SQUID_OS_SGI_H */
