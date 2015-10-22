/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SSL_BIO_H
#define SQUID_SSL_BIO_H

#include "fd.h"
#include "SBuf.h"

#include <iosfwd>
#include <list>
#if HAVE_OPENSSL_BIO_H
#include <openssl/bio.h>
#endif
#include <string>

namespace Ssl
{
class HandshakeParser {
public:
    /// The parsing states
    typedef enum {atHelloNone = 0, atHelloStarted, atHelloReceived, atCertificatesReceived, atHelloDoneReceived, atNstReceived, atCcsReceived, atFinishReceived} ParserState;

    /// TLS record protocol, content types, RFC5246 section 6.2.1
    typedef enum {ctNone = 0, ctChangeCipherSpec = 20, ctAlert = 21, ctHandshake = 22, ctApplicationData} ContentType;
    /// TLS Handshake protocol, handshake types, RFC5246  section 7.4
    typedef enum {hskNone = 0,  hskServerHello = 2, shkNewSessionTicket = 4, hskCertificate = 11, hskServerHelloDone = 14, hskFinished = 20} HandshakeType;

    HandshakeParser(): state(atHelloNone), currentContentType(ctNone), unParsedContent(0), parsingPos(0), currentMsg(0), currentMsgSize(0), certificatesMsgPos(0), certificatesMsgSize(0), ressumingSession(false), parseDone(false), parseError(false) {}

    /// Parses the SSL Server Hello records stored in data.
    /// Return false if the hello messages are not complete (HelloDone 
    /// or Finished handshake messages are not received)
    /// On parse error, return false and sets the parseError member to true.
    bool parseServerHello(const unsigned char *data, size_t dataSize);

    /// Parse server certificates message and store the certificate to serverCertificates list
    bool parseServerCertificates(Ssl::X509_STACK_Pointer &serverCertificates, const unsigned char *msg, size_t size);

    ParserState state; ///< current parsing state.

    ContentType currentContentType; ///< The current SSL record content type
    size_t unParsedContent; ///< The size of current SSL record, which is not parsed yet
    size_t parsingPos; ///< The parsing position from the beginning of parsed data
    size_t currentMsg; ///< The current handshake message possition from the beginning of parsed data
    size_t currentMsgSize; ///< The current handshake message size.

    size_t certificatesMsgPos; ///< The possition of certificates message from the beggining of parsed data
    size_t certificatesMsgSize; ///< The size of certificates message
    bool ressumingSession; ///< True if this is a resumming session

    bool parseDone; ///< The parser finishes its job
    bool parseError; ///< Set to tru by parse on parse error.

private:
    /// Do nothing if there are unparsed data from existing SSL record
    /// else parses the next SSL record.
    /// Return false if the next SSL record is not complete.
    bool parseNextContentRecord(const unsigned char *msg, size_t size);
    /// Consumes the current SSL record and set the parsingPos to the next
    bool skipContentDataRecord(const unsigned char *msg, size_t size);
    /// Parses the next handshake message in current SSL record
    HandshakeType parseNextHandshakeMessage(const unsigned char *msg, size_t size);
};

/// BIO source and sink node, handling socket I/O and monitoring SSL state
class Bio
{
public:
    enum Type {
        BIO_TO_CLIENT = 6000,
        BIO_TO_SERVER
    };

    /// Class to store SSL connection features
    class sslFeatures
    {
    public:
        sslFeatures();
        bool get(const SSL *ssl); ///< Retrieves the features from SSL object
        /// Retrieves features from raw SSL Hello message.
        /// \param record  whether to store Message to the helloMessage member
        bool get(const MemBuf &, bool record = true);
        /// Parses a v3 ClientHello message
        bool parseV3Hello(const unsigned char *hello, size_t helloSize);
        /// Parses a v23 ClientHello message
        bool parseV23Hello(const unsigned char *hello, size_t helloSize);
        /// Parses a v3 ServerHello message.
        bool parseV3ServerHello(const unsigned char *hello, size_t helloSize);
        /// Prints to os stream a human readable form of sslFeatures object
        std::ostream & print(std::ostream &os) const;
        /// Converts to the internal squid SSL version form the sslVersion
        int toSquidSSLVersion() const;
        /// Configure the SSL object with the SSL features of the sslFeatures object
        void applyToSSL(SSL *ssl, Ssl::BumpMode bumpMode) const;
        /// Parses an SSL Message header. It returns the ssl Message size.
        /// \retval >0 if the hello size is retrieved
        /// \retval 0 if the contents of the buffer are not enough
        /// \retval <0 if the contents of buf are not SSLv3 or TLS hello message
        int parseMsgHead(const MemBuf &);
    public:
        int sslVersion; ///< The requested/used SSL version
        int compressMethod; ///< The requested/used compressed  method
        int helloMsgSize; ///< the hello message size
        mutable SBuf serverName; ///< The SNI hostname, if any
        std::string clientRequestedCiphers; ///< The client requested ciphers
        bool unknownCiphers; ///< True if one or more ciphers are unknown
        std::string ecPointFormatList;///< tlsExtension ecPointFormatList
        std::string ellipticCurves; ///< tlsExtension ellipticCurveList
        std::string opaquePrf; ///< tlsExtension opaquePrf
        bool doHeartBeats;
        bool tlsTicketsExtension; ///< whether TLS tickets extension is enabled
        bool hasTlsTicket; ///< whether a TLS ticket is included
        bool tlsStatusRequest; ///< whether the TLS status request extension is set
        SBuf tlsAppLayerProtoNeg; ///< The value of the TLS application layer protocol extension if it is enabled
        /// The client random number
        unsigned char client_random[SSL3_RANDOM_SIZE];
        SBuf sessionId;
        std::list<int> extensions;
        SBuf helloMessage;
        bool initialized_;
    };
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
    static BIO *Create(const int fd, Type type);
    /// Tells ssl connection to use BIO and monitor state via stateChanged()
    static void Link(SSL *ssl, BIO *bio);

    /// Prepare the rbuf buffer to accept hello data
    void prepReadBuf();

    /// Reads data from socket and record them to a buffer
    int readAndBuffer(BIO *table, const char *description);

    const MemBuf &rBufData() {return rbuf;}
protected:
    const int fd_; ///< the SSL socket we are reading and writing
    MemBuf rbuf;  ///< Used to buffer input data.
};

/// BIO node to handle socket IO for squid client side
/// If bumping is enabled  this Bio detects and analyses client hello message
/// to retrieve the SSL features supported by the client
class ClientBio: public Bio
{
public:
    /// The ssl hello message read states
    typedef enum {atHelloNone = 0, atHelloStarted, atHelloReceived} HelloReadState;
    explicit ClientBio(const int anFd): Bio(anFd), holdRead_(false), holdWrite_(false), helloState(atHelloNone), helloSize(0), wrongProtocol(false) {}

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
    /// Return true if the client hello message received and analized
    bool gotHello() { return (helloState == atHelloReceived); }
    /// Return the SSL features requested by SSL client
    const Bio::sslFeatures &getFeatures() const {return features;}
    /// Prevents or allow writting on socket.
    void hold(bool h) {holdRead_ = holdWrite_ = h;}
    /// True if client does not looks like an SSL client
    bool noSslClient() {return wrongProtocol;}
private:
    /// True if the SSL state corresponds to a hello message
    bool isClientHello(int state);
    /// The futures retrieved from client SSL hello message
    Bio::sslFeatures features;
    bool holdRead_; ///< The read hold state of the bio.
    bool holdWrite_;  ///< The write hold state of the bio.
    HelloReadState helloState; ///< The SSL hello read state
    int helloSize; ///< The SSL hello message sent by client size
    bool wrongProtocol; ///< true if client SSL hello parsing failed
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
    explicit ServerBio(const int anFd): Bio(anFd), helloMsgSize(0), helloBuild(false), allowSplice(false), allowBump(false), holdWrite_(false), holdRead_(true), bumpMode_(bumpNone), rbufConsumePos(0) {}
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
    void setClientFeatures(const sslFeatures &features);

    bool resumingSession();

    /// Reads Server hello message+certificates+ServerHelloDone message sent
    /// by server and buffer it to rbuf member
    int readAndBufferServerHelloMsg(BIO *table, const char *description);

    /// The write hold state
    bool holdWrite() const {return holdWrite_;}
    /// Enables or disables the write hold state
    void holdWrite(bool h) {holdWrite_ = h;}
    /// The read hold state
    bool holdRead() const {return holdRead_;}
    /// Enables or disables the read hold state
    void holdRead(bool h) {holdRead_ = h;}
    /// Whether we can splice or not the SSL stream
    bool canSplice() {return allowSplice;}
    /// Whether we can bump or not the SSL stream
    bool canBump() {return allowBump;}
    /// The bumping mode
    void mode(Ssl::BumpMode m) {bumpMode_ = m;}
    Ssl::BumpMode bumpMode() {return bumpMode_;} ///< return the bumping mode

    /// Return true if the Server hello message received
    bool gotHello() const { return (parser_.parseDone && !parser_.parseError); }

    /// Return true if the Server Hello parsing failed
    bool gotHelloFailed() const { return (parser_.parseDone && parser_.parseError); }

    const Ssl::X509_STACK_Pointer &serverCertificates();
private:
    sslFeatures clientFeatures; ///< SSL client features extracted from ClientHello message or SSL object
    SBuf helloMsg; ///< Used to buffer output data.
    mb_size_t  helloMsgSize;
    bool helloBuild; ///< True if the client hello message sent to the server
    bool allowSplice; ///< True if the SSL stream can be spliced
    bool allowBump;  ///< True if the SSL stream can be bumped
    bool holdWrite_;  ///< The write hold state of the bio.
    bool holdRead_;  ///< The read hold state of the bio.
    Ssl::BumpMode bumpMode_;

    ///< The size of data stored in rbuf which passed to the openSSL
    size_t rbufConsumePos;
    HandshakeParser parser_; ///< The SSL messages parser.
    Ssl::X509_STACK_Pointer serverCertificates_; ///< The certificates chain sent by the SSL server
};

inline
std::ostream &operator <<(std::ostream &os, Ssl::Bio::sslFeatures const &f)
{
    return f.print(os);
}

} // namespace Ssl

#endif /* SQUID_SSL_BIO_H */

