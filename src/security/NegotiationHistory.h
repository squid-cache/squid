#ifndef SQUID_SRC_SECURITY_NEGOTIATION_HISTORY_H
#define SQUID_SRC_SECURITY_NEGOTIATION_HISTORY_H

#if USE_OPENSSL
#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#endif

namespace Security {
class NegotiationHistory
{
public:
    NegotiationHistory();
#if USE_OPENSSL
    void fillWith(SSL *); ///< Extract negotiation information from TLS object
#endif
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
    const char *printTlsVersion(int v) const;
    int helloVersion_; ///< The TLL version of the hello message
    int supportedVersion_; ///< The maximum supported TLS version
    int version_; ///< The negotiated TLL version
#if USE_OPENSSL
    const SSL_CIPHER *cipher; ///< The negotiated cipher
#endif
};

} // namespace Security

#endif /* SQUID_SRC_SECURITY_NEGOTIATION_HISTORY_H */

