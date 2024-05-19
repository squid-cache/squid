/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_IDENT_IDENT_H
#define SQUID_SRC_IDENT_IDENT_H

#include "comm/forward.h"
#include "sbuf/forward.h"

#include <optional>

/// Ident Lookup API
namespace Ident
{

/// A user-id field of RFC 1413 ident-reply response. The stored value is never
/// empty because RFC 1413 prohibits empty user-id fields.
using User = SBuf;

/// An Ident transaction attempt. Nil state indicates a failed attempt (e.g., a
/// state after an Ident server returned RFC 1413 error-reply).
using Lookup = std::optional<User>;

/// Start() callback function that receives Ident lookup outcome.
using IDCB = void (const Lookup &, void *data);

/**
 * Open a connection and request IDENT information from a peer machine.
 * Callback will be called when the lookup is completed.
 */
void Start(const Comm::ConnectionPointer &conn, IDCB * callback, void *cbdata);

} // namespace Ident

#endif /* SQUID_SRC_IDENT_IDENT_H */

