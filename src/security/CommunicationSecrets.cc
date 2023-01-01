/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base/IoManip.h"
#include "security/CommunicationSecrets.h"
#include "security/Session.h"

#include <ostream>

// TODO: Support SSL_CTX_set_keylog_callback() available since OpenSSL v1.1.1.

Security::CommunicationSecrets::CommunicationSecrets(const Connection &sconn)
{
#if USE_OPENSSL
    getClientRandom(sconn);

    if (const auto session = SSL_get_session(&sconn)) {
        getMasterKey(*session);
        getSessionId(*session);
    }
#else
    // Secret extraction is not supported in builds using other TLS libraries.
    // Secret extraction is impractical in builds without TLS libraries.
    (void)sconn;
#endif
}

bool
Security::CommunicationSecrets::gotAll() const
{
    return !id.isEmpty() && !random.isEmpty() && !key.isEmpty();
}

bool
Security::CommunicationSecrets::learnNew(const CommunicationSecrets &news)
{
    auto sawChange = false;

    if (id != news.id && !news.id.isEmpty()) {
        id = news.id;
        sawChange = true;
    }

    if (random != news.random && !news.random.isEmpty()) {
        random = news.random;
        sawChange = true;
    }

    if (key != news.key && !news.key.isEmpty()) {
        key = news.key;
        sawChange = true;
    }

    return sawChange;
}

/// writes the given secret (in hex) or, if there is no secret, a placeholder
static void
PrintSecret(std::ostream &os, const SBuf &secret)
{
    if (!secret.isEmpty())
        PrintHex(os, secret.rawContent(), secret.length());
    else
        os << '-';
}

void
Security::CommunicationSecrets::record(std::ostream &os) const {
    // Print SSLKEYLOGFILE blobs that contain at least one known secret.
    // See Wireshark tls_keylog_process_lines() source code for format details.

    // RSA Session-ID:... Master-Key:...
    if (id.length() || key.length()) {
        os << "RSA";
        PrintSecret(os << " Session-ID:", id);
        PrintSecret(os << " Master-Key:", key);
        os << "\n";
    }

    // CLIENT_RANDOM ... ...
    if (random.length() || key.length()) {
        os << "CLIENT_RANDOM ";
        PrintSecret(os, random);
        os << ' ';
        // we may have already printed the key on a separate Master-Key: line above,
        // but the CLIENT_RANDOM line format includes the same key info
        PrintSecret(os, key);
        os << "\n";
    }
}

#if USE_OPENSSL
/// Clears the given secret if it is likely to contain no secret information.
/// When asked for a secret too early, OpenSSL (successfully!) returns a copy of
/// the secret _storage_ (filled with zeros) rather than an actual secret.
static void
IgnorePlaceholder(SBuf &secret)
{
    static const auto NulChar = CharacterSet("NUL").add('\0');
    if (secret.findFirstNotOf(NulChar) == SBuf::npos) // all zeros
        secret.clear();
}

void
Security::CommunicationSecrets::getClientRandom(const Connection &sconn)
{
    random.clear();
    const auto expectedLength = SSL_get_client_random(&sconn, nullptr, 0);
    if (!expectedLength)
        return;

    // no auto due to reinterpret_casting of the result below
    char * const space = random.rawAppendStart(expectedLength);
    const auto actualLength = SSL_get_client_random(&sconn,
                              reinterpret_cast<unsigned char*>(space), expectedLength);
    random.rawAppendFinish(space, actualLength);

    IgnorePlaceholder(random);
}

void
Security::CommunicationSecrets::getSessionId(const Session &session)
{
    id.clear();
    unsigned int idLength = 0;
    // no auto due to reinterpret_casting of the result below
    const unsigned char * const idStart = SSL_SESSION_get_id(&session, &idLength);
    if (idStart && idLength)
        id.assign(reinterpret_cast<const char *>(idStart), idLength);

    IgnorePlaceholder(id);
}

void
Security::CommunicationSecrets::getMasterKey(const Session &session)
{
    key.clear();
    const auto expectedLength = SSL_SESSION_get_master_key(&session, nullptr, 0);
    if (!expectedLength)
        return;

    // no auto due to reinterpret_casting of the result below
    char * const space = key.rawAppendStart(expectedLength);
    const auto actualLength = SSL_SESSION_get_master_key(&session,
                              reinterpret_cast<unsigned char*>(space), expectedLength);
    key.rawAppendFinish(space, actualLength);

    IgnorePlaceholder(key);
}
#endif /* USE_OPENSSL */

