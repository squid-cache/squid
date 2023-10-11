/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CLIENTS_HTTP_TUNNELERANSWER_H
#define SQUID_SRC_CLIENTS_HTTP_TUNNELERANSWER_H

#include "base/CbcPointer.h"
#include "comm/Connection.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"

class ErrorState;

namespace Http {

/// Three mutually exclusive answers are possible:
///
/// * Squid-generated error object (TunnelerAnswer::squidError);
/// * peer-generated error message (TunnelerAnswer::peerError);
/// * successful tunnel establishment (none of the above are present).
///
/// HTTP CONNECT tunnel setup results (supplied via a callback). The tunnel
/// through the peer was established if and only if the error member is nil.
class TunnelerAnswer
{
public:
    TunnelerAnswer() {}
    ~TunnelerAnswer(); ///< deletes squidError if it is still set

    bool positive() const { return !squidError; }

    // Destructor will erase squidError if it is still set. Answer recipients
    // must clear this member to keep its info.
    // XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> squidError; ///< problem details (or nil)

    SBuf leftovers; ///< peer-generated bytes after a positive answer (or empty)

    /// the status code of the successfully parsed CONNECT response (or scNone)
    StatusCode peerResponseStatus = scNone;

    Comm::ConnectionPointer conn;
};

std::ostream &operator <<(std::ostream &, const TunnelerAnswer &);

} // namespace Http

#endif /* SQUID_SRC_CLIENTS_HTTP_TUNNELERANSWER_H */

