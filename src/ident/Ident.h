/*
 * Copyright (C) 1996-2019 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IDENT_H
#define SQUID_IDENT_H

#if USE_IDENT

#include "cbdata.h"
#include "comm/forward.h"

typedef void IDCB(const char *ident, void *data);

/// Ident Lookup API
namespace Ident
{

/**
 * Open a connection and request IDENT information from a peer machine.
 * Callack will be called whan the lookup is completed.
 * Self-registers with a global ident lookup manager,
 * will call Ident::Init() itself if the manager has not been initialized already.
 */
void Start(const Comm::ConnectionPointer &conn, IDCB * callback, void *cbdata);

/**
 * Initialize IDENT lookup manager.
 * Currently a hash list of open ident requests.
 */
void Init(void);

} // namespace Ident

#endif /* USE_IDENT */
#endif /* SQUID_IDENT_H */

