/*
 * $Id$
 */
#ifndef SQUID_IDENT_H
#define SQUID_IDENT_H

/**
 \defgroup IdentAPI Ident Lookup API
 \ingroup SquidComponents
 */

#include "config.h"

#if USE_IDENT

#include "cbdata.h"

class IpAddress;

namespace Ident
{

/**
  \ingroup IdentAPI
 *
 * Open a connection and request IDENT information from a peer machine.
 * Callack will be called whan the lookup is completed.
 * Self-registers with a global ident lookup manager,
 * will call Ident::Init() itself if the manager has not been initialized already.
 */
void Start(IpAddress &me, IpAddress &my_peer, IDCB * callback, void *cbdata);

/**
 \ingroup IdentAPI
 *
 * Initialize IDENT lookup manager.
 * Currently a hash list of open ident requests.
 * \bug Will leak the hash list if called twice.
 */
void Init(void);

}

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_H */
