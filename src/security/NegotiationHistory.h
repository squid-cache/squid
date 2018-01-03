/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SECURITY_NEGOTIATIONHISTORY_H
#define SQUID_SRC_SECURITY_NEGOTIATIONHISTORY_H

#include "anyp/ProtocolVersion.h"
#include "security/Handshake.h"
#include "security/Session.h"

namespace Security {

class NegotiationHistory
{
public:
    NegotiationHistory();

    /// Extract negotiation information from TLS object
    void retrieveNegotiatedInfo(const Security::SessionPointer &);

    /// Extract information from parser stored in TlsDetails  object
    void retrieveParsedInfo(Security::TlsDetails::Pointer const &details);

    const char *cipherName() const; ///< The name of negotiated cipher
    /// String representation of TLS negotiated version
    const char *negotiatedVersion() const {return printTlsVersion(version_);}
    /// String representation of the received TLS hello message version.
    const char *helloVersion() const {return printTlsVersion(helloVersion_);}
    /// String representation of the maximum supported TLS version
    /// by remote peer
    const char *supportedVersion() const {return printTlsVersion(supportedVersion_);}
private:
    /// String representation of the TLS version 'v'
    const char *printTlsVersion(AnyP::ProtocolVersion const &v) const;
    AnyP::ProtocolVersion helloVersion_; ///< The TLS version of the hello message
    AnyP::ProtocolVersion supportedVersion_; ///< The maximum supported TLS version
    AnyP::ProtocolVersion version_; ///< The negotiated TLS version
#if USE_OPENSSL
    const SSL_CIPHER *cipher; ///< The negotiated cipher
#endif
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_NEGOTIATIONHISTORY_H */

