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

class IPAddress;

/// \ingroup IdentAPI
SQUIDCEXTERN void identStart(IPAddress &me, IPAddress &my_peer, IDCB * callback, void *cbdata);

/// \ingroup IdentAPI
SQUIDCEXTERN void identInit(void);

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_H */
