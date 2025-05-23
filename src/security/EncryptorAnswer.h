/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_ENCRYPTORANSWER_H
#define SQUID_SRC_SECURITY_ENCRYPTORANSWER_H

#include "base/CbcPointer.h"
#include "comm/Connection.h"

class ErrorState;

namespace Security {

/// Peer encrypted connection setup results (supplied via a callback).
/// The connection to peer was secured if and only if the error member is nil.
class EncryptorAnswer
{
public:
    EncryptorAnswer(): tunneled(false) {}
    ~EncryptorAnswer(); ///< deletes error if it is still set
    Comm::ConnectionPointer conn; ///< peer connection (secured on success)

    /// answer recipients must clear the error member in order to keep its info
    /// XXX: We should refcount ErrorState instead of cbdata-protecting it.
    CbcPointer<ErrorState> error; ///< problem details (nil on success)

    /// whether we spliced the connections instead of negotiating encryption
    bool tunneled;
};

std::ostream &operator <<(std::ostream &, const EncryptorAnswer &);

} // namespace Security

#endif /* SQUID_SRC_SECURITY_ENCRYPTORANSWER_H */

