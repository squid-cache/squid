/*
 * $Id$
 */
#ifndef SQUID_IDENT_H
#define SQUID_IDENT_H

/*
 \defgroup IdentAPI Ident Lookup API
 \ingroup SquidComponents
 *
 */

#include "config.h"

#if USE_IDENT

#include "cbdata.h"

class IpAddress;

/// \ingroup IdentAPI
SQUIDCEXTERN void identStart(IpAddress &me, IpAddress &my_peer, IDCB * callback, void *cbdata);

/// \ingroup IdentAPI
SQUIDCEXTERN void identInit(void);

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_H */
