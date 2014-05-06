#ifndef SQUID_SSL_BIO_H
#define SQUID_SSL_BIO_H

#include "MemBuf.h"
#include <iosfwd>
#include <list>
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
    enum Type {
        BIO_TO_CLIENT = 6000,
        BIO_TO_SERVER
    };

    /// Class to store SSL connection features
    class sslFeatures {
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
    public:
        int sslVersion; ///< The requested/used SSL version
        int compressMethod; ///< The requested/used compressed  method
        std::string serverName; ///< The SNI hostname, if any
        std::string clientRequestedCiphers; ///< The client requested ciphers
        bool unknownCiphers; ///< True if one or more ciphers are unknown
        std::string ecPointFormatList;///< tlsExtension ecPointFormatList
        std::string ellipticCurves; ///< tlsExtension ellipticCurveList
        std::string opaquePrf; ///< tlsExtension opaquePrf
        bool doHeartBeats;
        /// The client random number
        unsigned char client_random[SSL3_RANDOM_SIZE];
        std::list<int> extensions;
        MemBuf helloMessage;
    };
    explicit Bio(const int anFd);
    ~Bio();

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

protected:
    const int fd_; ///< the SSL socket we are reading and writing
};

/// BIO node to handle socket IO for squid client side
class ClientBio: public Bio {
public:
    explicit ClientBio(const int anFd): Bio(anFd), holdRead_(false), holdWrite_(false), headerState(0), headerBytes(0) {}

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
    MemBuf rbuf;  ///< Used to buffer input data.
    int headerState;
    int headerBytes;
};

/// BIO node to handle socket IO for squid server side
class ServerBio: public Bio {
public:
    explicit ServerBio(const int anFd): Bio(anFd), featuresSet(false), helloMsgSize(0), helloBuild(false), allowSplice(false), holdWrite_(false), record_(false) {}
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

    bool holdWrite() const {return holdWrite_;}
    void holdWrite(bool h) {holdWrite_ = h;}
    void recordInput(bool r) {record_ = r;}
    const MemBuf &rBufData() {return rbuf;}
    bool canSplice() {return allowSplice;}
private:
    /// A random number to use as "client random" in client hello message
    sslFeatures clientFeatures;
    bool featuresSet; ///< True if the clientFeatures member is set and can be used
    MemBuf helloMsg; ///< Used to buffer output data.
    int helloMsgSize;
    bool helloBuild; ///< True if the client hello message sent to the server
    bool allowSplice;
    bool holdWrite_;  ///< The write hold state of the bio.
    bool record_;
    MemBuf rbuf;  ///< Used to buffer input data.
};

inline
std::ostream &operator <<(std::ostream &os, Ssl::Bio::sslFeatures const &f)
{
    return f.print(os);
}

} // namespace Ssl

#endif /* SQUID_SSL_BIO_H */
