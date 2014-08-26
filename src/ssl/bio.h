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
        bool get(const unsigned char *hello); ///< Retrieves the features from raw SSL hello message
        bool parseV3Hello(const unsigned char *hello);
        bool parseV23Hello(const unsigned char *hello);
        /// Prints to os stream a human readable form of sslFeatures object
        std::ostream & print(std::ostream &os) const;
        /// Converts to the internal squid SSL version form the sslVersion
        int toSquidSSLVersion() const;
        /// Configure the SSL object with the SSL features of the sslFeatures object
        void applyToSSL(SSL *ssl) const;
    public:
        int sslVersion; ///< The requested/used SSL version
        int compressMethod; ///< The requested/used compressed  method
        mutable SBuf serverName; ///< The SNI hostname, if any
        std::string clientRequestedCiphers; ///< The client requested ciphers
        bool unknownCiphers; ///< True if one or more ciphers are unknown
        std::string ecPointFormatList;///< tlsExtension ecPointFormatList
        std::string ellipticCurves; ///< tlsExtension ellipticCurveList
        std::string opaquePrf; ///< tlsExtension opaquePrf
        bool doHeartBeats;
        /// The client random number
        unsigned char client_random[SSL3_RANDOM_SIZE];
        std::list<int> extensions;
        SBuf helloMessage;
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
    explicit ClientBio(const int anFd): Bio(anFd), holdRead_(false), holdWrite_(false), helloState(atHelloNone), helloSize(0) {}

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
    bool gotHello() {return features.sslVersion != -1;}
    /// Return the SSL features requested by SSL client
    const Bio::sslFeatures &getFeatures() const {return features;}
    /// Prevents or allow writting on socket.
    void hold(bool h) {holdRead_ = holdWrite_ = h;}

private:
    /// True if the SSL state corresponds to a hello message
    bool isClientHello(int state);
    /// The futures retrieved from client SSL hello message
    Bio::sslFeatures features;
    bool holdRead_; ///< The read hold state of the bio.
    bool holdWrite_;  ///< The write hold state of the bio.
    HelloReadState helloState; ///< The SSL hello read state
    int helloSize; ///< The SSL hello message sent by client size
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
    explicit ServerBio(const int anFd): Bio(anFd), featuresSet(false), helloMsgSize(0), helloBuild(false), allowSplice(false), allowBump(false), holdWrite_(false), record_(false), bumpMode_(bumpNone) {}
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

    /// The write hold state
    bool holdWrite() const {return holdWrite_;}
    /// Enables or disables the write hold state
    void holdWrite(bool h) {holdWrite_ = h;}
    /// Enables or disables the input data recording, for internal analysis.
    void recordInput(bool r) {record_ = r;}
    /// Whether we can splice or not the SSL stream
    bool canSplice() {return allowSplice;}
    /// Whether we can bump or not the SSL stream
    bool canBump() {return allowBump;}
    /// The bumping mode
    void mode(Ssl::BumpMode m) {bumpMode_ = m;}
private:
    /// A random number to use as "client random" in client hello message
    sslFeatures clientFeatures;
    bool featuresSet; ///< True if the clientFeatures member is set and can be used
    SBuf helloMsg; ///< Used to buffer output data.
    mb_size_t  helloMsgSize;
    bool helloBuild; ///< True if the client hello message sent to the server
    bool allowSplice; ///< True if the SSL stream can be spliced
    bool allowBump;  ///< True if the SSL stream can be bumped
    bool holdWrite_;  ///< The write hold state of the bio.
    bool record_; ///< If true the input data recorded to rbuf for internal use
    Ssl::BumpMode bumpMode_;
};

inline
std::ostream &operator <<(std::ostream &os, Ssl::Bio::sslFeatures const &f)
{
    return f.print(os);
}

} // namespace Ssl

#endif /* SQUID_SSL_BIO_H */
