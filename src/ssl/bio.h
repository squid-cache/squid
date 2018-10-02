/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_BIO_H
#define SQUID_SSL_BIO_H

#if USE_OPENSSL

#include "compat/openssl.h"
#include "FadingCounter.h"
#include "fd.h"
#include "MemBuf.h"
#include "security/Handshake.h"
#include "ssl/support.h"

#include <iosfwd>
#include <list>
#if HAVE_OPENSSL_BIO_H
#include <openssl/bio.h>
#endif
#include <string>
#include <type_traits>

namespace Ssl
{

/// BIO source and sink node, handling socket I/O and monitoring SSL state
class Bio
{
public:
    explicit Bio(const int anFd);
    virtual ~Bio();

    /// Writes the given data to socket
    virtual int write(const char *buf, int size, BIO *table);

    /// Reads data from socket
    virtual int read(char *buf, int size, BIO *table);

    /// Flushes any buffered data to socket.
    /// The Ssl::Bio does not buffer any data, so this method has nothing to do
    virtual void flush(BIO *table) {}

    int fd() const { return fd_; } ///< The SSL socket descriptor

    /// Called by linked SSL connection whenever state changes, an alert
    /// appears, or an error occurs. See SSL_set_info_callback().
    virtual void stateChanged(const SSL *ssl, int where, int ret);

    /// Creates a low-level BIO table, creates a high-level Ssl::Bio object
    /// for a given socket, and then links the two together via BIO_C_SET_FD.
    static BIO *Create(const int fd, Security::Io::Type type);
    /// Tells ssl connection to use BIO and monitor state via stateChanged()
    static void Link(SSL *ssl, BIO *bio);

    const SBuf &rBufData() {return rbuf;} ///< The buffered input data
protected:
    const int fd_; ///< the SSL socket we are reading and writing
    SBuf rbuf;  ///< Used to buffer input data.
};

/// BIO node to handle socket IO for squid client side
/// If bumping is enabled  this Bio detects and analyses client hello message
/// to retrieve the SSL features supported by the client
class ClientBio: public Bio
{
public:
    explicit ClientBio(const int anFd);

    /// The ClientBio version of the Ssl::Bio::stateChanged method
    /// When the client hello message retrieved, fill the
    /// "features" member with the client provided informations.
    virtual void stateChanged(const SSL *ssl, int where, int ret);
    /// The ClientBio version of the Ssl::Bio::write method
    virtual int write(const char *buf, int size, BIO *table);
    /// The ClientBio version of the Ssl::Bio::read method
    /// If the holdRead flag is true then it does not write any data
    /// to socket and sets the "read retry" flag of the BIO to true
    virtual int read(char *buf, int size, BIO *table);
    /// Prevents or allow writting on socket.
    void hold(bool h) {holdRead_ = holdWrite_ = h;}

    /// Sets the buffered input data (Bio::rbuf).
    /// Used to pass payload data (normally client HELLO data) retrieved
    /// by the caller.
    void setReadBufData(SBuf &data) {rbuf = data;}
private:
    /// approximate size of a time window for computing client-initiated renegotiation rate (in seconds)
    static const time_t RenegotiationsWindow = 10;

    /// the maximum tolerated number of client-initiated renegotiations in RenegotiationsWindow
    static const int RenegotiationsLimit = 5;

    bool holdRead_; ///< The read hold state of the bio.
    bool holdWrite_;  ///< The write hold state of the bio.
    int helloSize; ///< The SSL hello message sent by client size
    FadingCounter renegotiations; ///< client requested renegotiations limit control

    /// why we should terminate the connection during next TLS operation (or nil)
    const char *abortReason;
};

/// BIO node to handle socket IO for squid server side
/// If bumping is enabled, analyses the SSL hello message sent by squid OpenSSL
/// subsystem (step3 bumping step) against bumping mode:
///   * Peek mode:  Send client hello message instead of the openSSL generated
///                 hello message and normaly denies bumping and allow only
///                 splice or terminate the SSL connection
///   * Stare mode: Sends the openSSL generated hello message and normaly
///                 denies splicing and allow bump or terminate the SSL
///                 connection
///  If SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK is enabled also checks if the
///  openSSL library features are compatible with the features reported in
///  web client SSL hello message and if it is, overwrites the openSSL SSL
///  object members to replace hello message with web client hello message.
///  This is may allow bumping in peek mode and splicing in stare mode after
///  the server hello message received.
class ServerBio: public Bio
{
public:
    explicit ServerBio(const int anFd);

    /// The ServerBio version of the Ssl::Bio::stateChanged method
    virtual void stateChanged(const SSL *ssl, int where, int ret);
    /// The ServerBio version of the Ssl::Bio::write method
    /// If a clientRandom number is set then rewrites the raw hello message
    /// "client random" field with the provided random number.
    /// It may buffer the output packets.
    virtual int write(const char *buf, int size, BIO *table);
    /// The ServerBio version of the Ssl::Bio::read method
    /// If the record flag is set then append the data to the rbuf member
    virtual int read(char *buf, int size, BIO *table);
    /// The ServerBio version of the Ssl::Bio::flush method.
    /// Flushes any buffered data
    virtual void flush(BIO *table);
    /// Sets the random number to use in client SSL HELLO message
    void setClientFeatures(Security::TlsDetails::Pointer const &details, SBuf const &hello);

    bool resumingSession();

    /// The write hold state
    bool holdWrite() const {return holdWrite_;}
    /// Enables or disables the write hold state
    void holdWrite(bool h) {holdWrite_ = h;}
    /// The read hold state
    bool holdRead() const {return holdRead_;}
    /// Enables or disables the read hold state
    void holdRead(bool h) {holdRead_ = h;}
    /// Enables or disables the input data recording, for internal analysis.
    void recordInput(bool r) {record_ = r;}
    /// Whether we can splice or not the SSL stream
    bool canSplice() {return allowSplice;}
    /// Whether we can bump or not the SSL stream
    bool canBump() {return allowBump;}
    /// The bumping mode
    void mode(Ssl::BumpMode m) {bumpMode_ = m;}
    Ssl::BumpMode bumpMode() {return bumpMode_;} ///< return the bumping mode

    /// \retval true if the Server hello message received
    bool gotHello() const { return (parsedHandshake && !parseError); }

    /// Return true if the Server Hello parsing failed
    bool gotHelloFailed() const { return (parsedHandshake && parseError); }

    /// \return the server certificates list if received and parsed correctly
    const Security::CertList &serverCertificatesIfAny() { return parser_.serverCertificates; }

    /// \return the TLS Details advertised by TLS server.
    const Security::TlsDetails::Pointer &receivedHelloDetails() const {return parser_.details;}

private:
    int readAndGive(char *buf, const int size, BIO *table);
    int readAndParse(char *buf, const int size, BIO *table);
    int readAndBuffer(BIO *table);
    int giveBuffered(char *buf, const int size);

    /// SSL client features extracted from ClientHello message or SSL object
    Security::TlsDetails::Pointer clientTlsDetails;
    /// TLS client hello message, used to adapt our tls Hello message to the server
    SBuf clientSentHello;
    SBuf helloMsg; ///< Used to buffer output data.
    mb_size_t  helloMsgSize;
    bool helloBuild; ///< True if the client hello message sent to the server
    bool allowSplice; ///< True if the SSL stream can be spliced
    bool allowBump;  ///< True if the SSL stream can be bumped
    bool holdWrite_;  ///< The write hold state of the bio.
    bool holdRead_;  ///< The read hold state of the bio.
    bool record_; ///< If true the input data recorded to rbuf for internal use
    bool parsedHandshake; ///< whether we are done parsing TLS Hello
    bool parseError; ///< error while parsing server hello message
    Ssl::BumpMode bumpMode_;

    /// The size of data stored in rbuf which passed to the openSSL
    size_t rbufConsumePos;
    Security::HandshakeParser parser_; ///< The TLS/SSL messages parser.
};

} // namespace Ssl

void
applyTlsDetailsToSSL(SSL *ssl, Security::TlsDetails::Pointer const &details, Ssl::BumpMode bumpMode);

#endif /* USE_OPENSSL */
#endif /* SQUID_SSL_BIO_H */

