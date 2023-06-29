/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H
#define SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H

#include "sbuf/SBuf.h"
#include "security/forward.h"

#include <iosfwd>

namespace Security {

/// extracts and formats TLS exchange info for (later) decryption that exchange:
/// early secrets, handshake secrets, (pre)master key, client random, etc.
class CommunicationSecrets
{
public:
    CommunicationSecrets() = default;
    explicit CommunicationSecrets(const Connection &sconn);

    /// whether we know all the secrets that could be extracted
    bool gotAll() const;

    /// copy all new secrets (i.e. previously unknown or changed)
    /// while preserving previously known secrets that have disappeared
    /// \returns whether any secrets were copied (i.e. this object has changed)
    bool learnNew(const CommunicationSecrets &news);

    /// logs all known secrets using a (multiline) SSLKEYLOGFILE format
    void record(std::ostream &) const;

private:
#if USE_OPENSSL
    void getClientRandom(const Connection &sconn);
    void getSessionId(const Session &session);
    void getMasterKey(const Session &session);
#else
    // Secret extraction is not supported in builds using other TLS libraries.
    // Secret extraction is impractical in builds without TLS libraries.
#endif

    SBuf id; ///< TLS session ID
    SBuf random; ///< CLIENT_RANDOM from the TLS connection
    SBuf key; ///< TLS session (pre-)master key
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_COMMUNICATION_SECRETS_H */

