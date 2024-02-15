/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IDENT_IDENT_H
#define SQUID_SRC_IDENT_IDENT_H

#include "cbdata.h"
#include "comm/forward.h"
#include "sbuf/forward.h"

#include <optional>

typedef void IDCB(const char *ident, void *data);

/// Ident Lookup API
namespace Ident
{

/// A user-id field of an RFC 931 auth-reply response.
/// Value existence implies that there was an attempt to obtain a valid user-id.
/// A non-empty value implies that the above attempt was successful.
using User = std::optional<SBuf>;

/**
 * Open a connection and request IDENT information from a peer machine.
 * Callback will be called when the lookup is completed.
 */
void Start(const Comm::ConnectionPointer &conn, IDCB * callback, void *cbdata);

} // namespace Ident

#endif /* SQUID_SRC_IDENT_IDENT_H */

