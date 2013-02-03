#ifndef SQUID_SSL_BIO_H
#define SQUID_SSL_BIO_H

#if HAVE_OPENSSL_BIO_H
#include <openssl/bio.h>
#endif
#if HAVE_STRING
#include <string>
#endif

namespace Ssl {

/// BIO source and sink node, handling socket I/O and monitoring SSL state
class Bio {
public:
    explicit Bio(const int anFd);
    ~Bio();

    int write(const char *buf, int size, BIO *table);
    int read(char *buf, int size, BIO *table);
    void flush() {} // we do not buffer (yet?)

    int fd() const { return fd_; }

    /// Called by linked SSL connection whenever state changes, an alert
    /// appears, or an error occurs. See SSL_set_info_callback().
    void stateChanged(const SSL *ssl, int where, int ret);

    /// Creates a low-level BIO table, creates a high-level Ssl::Bio object
    /// for a given socket, and then links the two together via BIO_C_SET_FD.
    static BIO *Create(const int fd);
    /// Tells ssl connection to use BIO and monitor state via stateChanged()
    static void Link(SSL *ssl, BIO *bio);

private:
    const int fd_; ///< the SSL socket we are reading and writing
};

} // namespace Ssl

#endif /* SQUID_SSL_BIO_H */
