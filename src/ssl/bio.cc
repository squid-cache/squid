/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 83    SSL accelerator support */

#include "squid.h"
#include "ssl/support.h"

/* support.cc says this is needed */
#if USE_OPENSSL

#include "comm.h"
#include "fde.h"
#include "globals.h"
#include "ip/Address.h"
#include "Mem.h"
#include "ssl/bio.h"

#if HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif

#if _SQUID_WINDOWS_
extern int socket_read_method(int, char *, int);
extern int socket_write_method(int, const char *, int);
#endif

/* BIO callbacks */
static int squid_bio_write(BIO *h, const char *buf, int num);
static int squid_bio_read(BIO *h, char *buf, int size);
static int squid_bio_puts(BIO *h, const char *str);
//static int squid_bio_gets(BIO *h, char *str, int size);
static long squid_bio_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int squid_bio_create(BIO *h);
static int squid_bio_destroy(BIO *data);
/* SSL callbacks */
static void squid_ssl_info(const SSL *ssl, int where, int ret);

/// Initialization structure for the BIO table with
/// Squid-specific methods and BIO method wrappers.
static BIO_METHOD SquidMethods = {
    BIO_TYPE_SOCKET,
    "squid",
    squid_bio_write,
    squid_bio_read,
    squid_bio_puts,
    NULL, // squid_bio_gets not supported
    squid_bio_ctrl,
    squid_bio_create,
    squid_bio_destroy,
    NULL // squid_callback_ctrl not supported
};

BIO *
Ssl::Bio::Create(const int fd, Ssl::Bio::Type type)
{
    if (BIO *bio = BIO_new(&SquidMethods)) {
        BIO_int_ctrl(bio, BIO_C_SET_FD, type, fd);
        return bio;
    }
    return NULL;
}

void
Ssl::Bio::Link(SSL *ssl, BIO *bio)
{
    SSL_set_bio(ssl, bio, bio); // cannot fail
    SSL_set_info_callback(ssl, &squid_ssl_info); // does not provide diagnostic
}

Ssl::Bio::Bio(const int anFd): fd_(anFd)
{
    debugs(83, 7, "Bio constructed, this=" << this << " FD " << fd_);
}

Ssl::Bio::~Bio()
{
    debugs(83, 7, "Bio destructing, this=" << this << " FD " << fd_);
}

int Ssl::Bio::write(const char *buf, int size, BIO *table)
{
    errno = 0;
#if _SQUID_WINDOWS_
    const int result = socket_write_method(fd_, buf, size);
#else
    const int result = default_write_method(fd_, buf, size);
#endif
    const int xerrno = errno;
    debugs(83, 5, "FD " << fd_ << " wrote " << result << " <= " << size);

    BIO_clear_retry_flags(table);
    if (result < 0) {
        const bool ignoreError = ignoreErrno(xerrno) != 0;
        debugs(83, 5, "error: " << xerrno << " ignored: " << ignoreError);
        if (ignoreError)
            BIO_set_retry_write(table);
    }

    return result;
}

int
Ssl::Bio::read(char *buf, int size, BIO *table)
{
    errno = 0;
#if _SQUID_WINDOWS_
    const int result = socket_read_method(fd_, buf, size);
#else
    const int result = default_read_method(fd_, buf, size);
#endif
    const int xerrno = errno;
    debugs(83, 5, "FD " << fd_ << " read " << result << " <= " << size);

    BIO_clear_retry_flags(table);
    if (result < 0) {
        const bool ignoreError = ignoreErrno(xerrno) != 0;
        debugs(83, 5, "error: " << xerrno << " ignored: " << ignoreError);
        if (ignoreError)
            BIO_set_retry_read(table);
    }

    return result;
}

int
Ssl::Bio::readAndBuffer(char *buf, int size, BIO *table, const char *description)
{
    prepReadBuf();

    size = min((int)rbuf.potentialSpaceSize(), size);
    if (size <= 0) {
        debugs(83, DBG_IMPORTANT, "Not enough space to hold " <<
               rbuf.contentSize() << "+ byte " << description);
        return -1;
    }

    const int bytes = Ssl::Bio::read(buf, size, table);
    debugs(83, 5, "read " << bytes << " out of " << size << " bytes"); // move to Ssl::Bio::read()

    if (bytes > 0) {
        rbuf.append(buf, bytes);
        debugs(83, 5, "recorded " << bytes << " bytes of " << description);
    }
    return bytes;
}

/// Called whenever the SSL connection state changes, an alert appears, or an
/// error occurs. See SSL_set_info_callback().
void
Ssl::Bio::stateChanged(const SSL *ssl, int where, int ret)
{
    // Here we can use (where & STATE) to check the current state.
    // Many STATE values are possible, including: SSL_CB_CONNECT_LOOP,
    // SSL_CB_ACCEPT_LOOP, SSL_CB_HANDSHAKE_START, and SSL_CB_HANDSHAKE_DONE.
    // For example:
    // if (where & SSL_CB_HANDSHAKE_START)
    //    debugs(83, 9, "Trying to establish the SSL connection");
    // else if (where & SSL_CB_HANDSHAKE_DONE)
    //    debugs(83, 9, "SSL connection established");

    debugs(83, 7, "FD " << fd_ << " now: 0x" << std::hex << where << std::dec << ' ' <<
           SSL_state_string(ssl) << " (" << SSL_state_string_long(ssl) << ")");
}

void
Ssl::Bio::prepReadBuf()
{
    if (rbuf.isNull())
        rbuf.init(4096, 65536);
}

bool
Ssl::ClientBio::isClientHello(int state)
{
    return (
#if defined(SSL2_ST_GET_CLIENT_HELLO_A)
               state == SSL2_ST_GET_CLIENT_HELLO_A ||
#endif
               state == SSL3_ST_SR_CLNT_HELLO_A ||
               state == SSL23_ST_SR_CLNT_HELLO_A ||
               state == SSL23_ST_SR_CLNT_HELLO_B ||
               state == SSL3_ST_SR_CLNT_HELLO_B ||
               state == SSL3_ST_SR_CLNT_HELLO_C
           );
}

void
Ssl::ClientBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
}

int
Ssl::ClientBio::write(const char *buf, int size, BIO *table)
{
    if (holdWrite_) {
        BIO_set_retry_write(table);
        return 0;
    }

    return Ssl::Bio::write(buf, size, table);
}

const char *objToString(unsigned char const *bytes, int len)
{
    static std::string buf;
    buf.clear();
    for (int i = 0; i < len; i++ ) {
        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%.2x", bytes[i]);
        buf.append(tmp);
    }
    return buf.c_str();
}

int
Ssl::ClientBio::read(char *buf, int size, BIO *table)
{
    if (helloState < atHelloReceived) {
        int bytes = readAndBuffer(buf, size, table, "TLS client Hello");
        if (bytes <= 0)
            return bytes;
    }

    if (helloState == atHelloNone) {
        helloSize = features.parseMsgHead(rbuf);
        if (helloSize == 0) {
            // Not enough bytes to get hello message size
            BIO_set_retry_read(table);
            return -1;
        } else if (helloSize < 0) {
            return -1;
        }

        helloState = atHelloStarted; //Next state
    }

    if (helloState == atHelloStarted) {
        const unsigned char *head = (const unsigned char *)rbuf.content();
        const char *s = objToString(head, rbuf.contentSize());
        debugs(83, 7, "SSL Header: " << s);

        if (helloSize > rbuf.contentSize()) {
            BIO_set_retry_read(table);
            return -1;
        }
        features.get(rbuf);
        helloState = atHelloReceived;
    }

    if (holdRead_) {
        debugs(83, 7, "Hold flag is set, retry latter. (Hold " << size << "bytes)");
        BIO_set_retry_read(table);
        return -1;
    }

    if (helloState == atHelloReceived) {
        if (rbuf.hasContent()) {
            int bytes = (size <= rbuf.contentSize() ? size : rbuf.contentSize());
            memcpy(buf, rbuf.content(), bytes);
            rbuf.consume(bytes);
            return bytes;
        } else
            return Ssl::Bio::read(buf, size, table);
    }

    return -1;
}

void
Ssl::ServerBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
}

void
Ssl::ServerBio::setClientFeatures(const Ssl::Bio::sslFeatures &features)
{
    clientFeatures = features;
};

int
Ssl::ServerBio::read(char *buf, int size, BIO *table)
{
    return record_ ?
           readAndBuffer(buf, size, table, "TLS server Hello") : Ssl::Bio::read(buf, size, table);
}

// This function makes the required checks to examine if the client hello
// message is compatible with the features provided by OpenSSL toolkit.
// If the features are compatible and can be supported it tries to rewrite SSL
// structure members, to replace the hello message created by openSSL, with the
// web client SSL hello message.
// This is mostly possible in the cases where the web client uses openSSL
// library similar with this one used by squid.
static bool
adjustSSL(SSL *ssl, Ssl::Bio::sslFeatures &features)
{
#if SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK
    if (!ssl->s3) {
        debugs(83, 5, "No SSLv3 data found!");
        return false;
    }

    // If the client supports compression but our context does not support
    // we can not adjust.
#if !defined(OPENSSL_NO_COMP)
    const bool requireCompression = (features.compressMethod && ssl->ctx->comp_methods == NULL);
#else
    const bool requireCompression = features.compressMethod;
#endif
    if (requireCompression) {
        debugs(83, 5, "Client Hello Data supports compression, but we do not!");
        return false;
    }

    // Check ciphers list
    size_t token = 0;
    size_t end = 0;
    while (token != std::string::npos) {
        end = features.clientRequestedCiphers.find(':',token);
        std::string cipher;
        cipher.assign(features.clientRequestedCiphers, token, end - token);
        token = (end != std::string::npos ? end + 1 : std::string::npos);
        bool found = false;
        STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(ssl);
        for (int i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);
            const char *cname = SSL_CIPHER_get_name(c);
            if (cipher.compare(cname)) {
                found = true;
                break;
            }
        }
        if (!found) {
            debugs(83, 5, "Client Hello Data supports cipher '"<< cipher <<"' but we do not support it!");
            return false;
        }
    }

#if !defined(SSL_TLSEXT_HB_ENABLED)
    if (features.doHeartBeats) {
        debugs(83, 5, "Client Hello Data supports HeartBeats but we do not support!");
        return false;
    }
#endif

    for (std::list<int>::iterator it = features.extensions.begin(); it != features.extensions.end(); ++it) {
        static int supportedExtensions[] = {
#if defined(TLSEXT_TYPE_server_name)
            TLSEXT_TYPE_server_name,
#endif
#if defined(TLSEXT_TYPE_opaque_prf_input)
            TLSEXT_TYPE_opaque_prf_input,
#endif
#if defined(TLSEXT_TYPE_heartbeat)
            TLSEXT_TYPE_heartbeat,
#endif
#if defined(TLSEXT_TYPE_renegotiate)
            TLSEXT_TYPE_renegotiate,
#endif
#if defined(TLSEXT_TYPE_ec_point_formats)
            TLSEXT_TYPE_ec_point_formats,
#endif
#if defined(TLSEXT_TYPE_elliptic_curves)
            TLSEXT_TYPE_elliptic_curves,
#endif
#if defined(TLSEXT_TYPE_session_ticket)
            TLSEXT_TYPE_session_ticket,
#endif
#if defined(TLSEXT_TYPE_status_request)
            TLSEXT_TYPE_status_request,
#endif
#if defined(TLSEXT_TYPE_use_srtp)
            TLSEXT_TYPE_use_srtp,
#endif
#if 0 //Allow 13172 Firefox supported extension for testing purposes
            13172,
#endif
            -1
        };
        bool found = false;
        for (int i = 0; supportedExtensions[i] != -1; i++) {
            if (*it == supportedExtensions[i]) {
                found = true;
                break;
            }
        }
        if (!found) {
            debugs(83, 5, "Extension " << *it <<  " does not supported!");
            return false;
        }
    }

    SSL3_BUFFER *wb=&(ssl->s3->wbuf);
    if (wb->len < (size_t)features.helloMessage.length())
        return false;

    debugs(83, 5, "OpenSSL SSL struct will be adjusted to mimic client hello data!");

    //Adjust ssl structure data.
    // We need to fix the random in SSL struct:
    memcpy(ssl->s3->client_random, features.client_random, SSL3_RANDOM_SIZE);
    memcpy(wb->buf, features.helloMessage.rawContent(), features.helloMessage.length());
    wb->left = features.helloMessage.length();

    size_t mainHelloSize = features.helloMessage.length() - 5;
    const char *mainHello = features.helloMessage.rawContent() + 5;
    assert((size_t)ssl->init_buf->max > mainHelloSize);
    memcpy(ssl->init_buf->data, mainHello, mainHelloSize);
    debugs(83, 5, "Hello Data init and adjustd sizes :" << ssl->init_num << " = "<< mainHelloSize);
    ssl->init_num = mainHelloSize;
    ssl->s3->wpend_ret = mainHelloSize;
    ssl->s3->wpend_tot = mainHelloSize;
    return true;
#else
    return false;
#endif
}

int
Ssl::ServerBio::write(const char *buf, int size, BIO *table)
{

    if (holdWrite_) {
        debugs(83, 7,  "Hold write, for SSL connection on " << fd_ << "will not write bytes of size " << size);
        BIO_set_retry_write(table);
        return -1;
    }

    if (!helloBuild && (bumpMode_ == Ssl::bumpPeek || bumpMode_ == Ssl::bumpStare)) {
        if (
            buf[1] >= 3  //it is an SSL Version3 message
            && buf[0] == 0x16 // and it is a Handshake/Hello message
        ) {

            //Hello message is the first message we write to server
            assert(helloMsg.isEmpty());

            SSL *ssl = fd_table[fd_].ssl;
            if (clientFeatures.initialized_ && ssl) {
                if (bumpMode_ == Ssl::bumpPeek) {
                    if (adjustSSL(ssl, clientFeatures))
                        allowBump = true;
                    allowSplice = true;
                    helloMsg.append(clientFeatures.helloMessage);
                    debugs(83, 7,  "SSL HELLO message for FD " << fd_ << ": Random number is adjusted for peek mode");
                } else { /*Ssl::bumpStare*/
                    allowBump = true;
                    if (adjustSSL(ssl, clientFeatures)) {
                        allowSplice = true;
                        helloMsg.append(clientFeatures.helloMessage);
                        debugs(83, 7,  "SSL HELLO message for FD " << fd_ << ": Random number is adjusted for stare mode");
                    }
                }
            }
        }
        // If we do not build any hello message, copy the current
        if (helloMsg.isEmpty())
            helloMsg.append(buf, size);

        helloBuild = true;
        helloMsgSize = helloMsg.length();
        //allowBump = true;

        if (allowSplice) {
            // Do not write yet.....
            BIO_set_retry_write(table);
            return -1;
        }
    }

    if (!helloMsg.isEmpty()) {
        debugs(83, 7,  "buffered write for FD " << fd_);
        int ret = Ssl::Bio::write(helloMsg.rawContent(), helloMsg.length(), table);
        helloMsg.consume(ret);
        if (!helloMsg.isEmpty()) {
            // We need to retry sendind data.
            // Say to openSSL to retry sending hello message
            BIO_set_retry_write(table);
            return -1;
        }

        // Sending hello message complete. Do not send more data for now...
        holdWrite_ = true;

        // spoof openSSL that we write what it ask us to write
        return size;
    } else
        return Ssl::Bio::write(buf, size, table);
}

void
Ssl::ServerBio::flush(BIO *table)
{
    if (!helloMsg.isEmpty()) {
        int ret = Ssl::Bio::write(helloMsg.rawContent(), helloMsg.length(), table);
        helloMsg.consume(ret);
    }
}

bool
Ssl::ServerBio::resumingSession()
{
    if (!serverFeatures.initialized_)
        serverFeatures.get(rbuf, false);

    if (!clientFeatures.sessionId.isEmpty() && !serverFeatures.sessionId.isEmpty())
        return clientFeatures.sessionId == serverFeatures.sessionId;

    // is this a session resuming attempt using TLS tickets?
    if (clientFeatures.hasTlsTicket && serverFeatures.hasCcsOrNst)
        return true;

    return false;
}

/// initializes BIO table after allocation
static int
squid_bio_create(BIO *bi)
{
    bi->init = 0; // set when we store Bio object and socket fd (BIO_C_SET_FD)
    bi->num = 0;
    bi->ptr = NULL;
    bi->flags = 0;
    return 1;
}

/// cleans BIO table before deallocation
static int
squid_bio_destroy(BIO *table)
{
    delete static_cast<Ssl::Bio*>(table->ptr);
    table->ptr = NULL;
    return 1;
}

/// wrapper for Bio::write()
static int
squid_bio_write(BIO *table, const char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
    assert(bio);
    return bio->write(buf, size, table);
}

/// wrapper for Bio::read()
static int
squid_bio_read(BIO *table, char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
    assert(bio);
    return bio->read(buf, size, table);
}

/// implements puts() via write()
static int
squid_bio_puts(BIO *table, const char *str)
{
    assert(str);
    return squid_bio_write(table, str, strlen(str));
}

/// other BIO manipulations (those without dedicated callbacks in BIO table)
static long
squid_bio_ctrl(BIO *table, int cmd, long arg1, void *arg2)
{
    debugs(83, 5, table << ' ' << cmd << '(' << arg1 << ", " << arg2 << ')');

    switch (cmd) {
    case BIO_C_SET_FD: {
        assert(arg2);
        const int fd = *static_cast<int*>(arg2);
        Ssl::Bio *bio;
        if (arg1 == Ssl::Bio::BIO_TO_SERVER)
            bio = new Ssl::ServerBio(fd);
        else
            bio = new Ssl::ClientBio(fd);
        assert(!table->ptr);
        table->ptr = bio;
        table->init = 1;
        return 0;
    }

    case BIO_C_GET_FD:
        if (table->init) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
            assert(bio);
            if (arg2)
                *static_cast<int*>(arg2) = bio->fd();
            return bio->fd();
        }
        return -1;

    case BIO_CTRL_DUP:
        // Should implemented if the SSL_dup openSSL API function
        // used anywhere in squid.
        return 0;

    case BIO_CTRL_FLUSH:
        if (table->init) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr);
            assert(bio);
            bio->flush(table);
            return 1;
        }
        return 0;

    /*  we may also need to implement these:
        case BIO_CTRL_RESET:
        case BIO_C_FILE_SEEK:
        case BIO_C_FILE_TELL:
        case BIO_CTRL_INFO:
        case BIO_CTRL_GET_CLOSE:
        case BIO_CTRL_SET_CLOSE:
        case BIO_CTRL_PENDING:
        case BIO_CTRL_WPENDING:
    */
    default:
        return 0;

    }

    return 0; /* NOTREACHED */
}

/// wrapper for Bio::stateChanged()
static void
squid_ssl_info(const SSL *ssl, int where, int ret)
{
    if (BIO *table = SSL_get_rbio(ssl)) {
        if (Ssl::Bio *bio = static_cast<Ssl::Bio*>(table->ptr))
            bio->stateChanged(ssl, where, ret);
    }
}

Ssl::Bio::sslFeatures::sslFeatures(): sslVersion(-1), compressMethod(-1), helloMsgSize(0), unknownCiphers(false), doHeartBeats(true), tlsTicketsExtension(false), hasTlsTicket(false), tlsStatusRequest(false), hasCcsOrNst(false), initialized_(false)
{
    memset(client_random, 0, SSL3_RANDOM_SIZE);
}

int Ssl::Bio::sslFeatures::toSquidSSLVersion() const
{
    if (sslVersion == SSL2_VERSION)
        return 2;
    else if (sslVersion == SSL3_VERSION)
        return 3;
    else if (sslVersion == TLS1_VERSION)
        return 4;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    else if (sslVersion == TLS1_1_VERSION)
        return 5;
    else if (sslVersion == TLS1_2_VERSION)
        return 6;
#endif
    else
        return 1;
}

bool
Ssl::Bio::sslFeatures::get(const SSL *ssl)
{
    sslVersion = SSL_version(ssl);
    debugs(83, 7, "SSL version: " << SSL_get_version(ssl) << " (" << sslVersion << ")");

#if defined(TLSEXT_NAMETYPE_host_name)
    if (const char *server = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
        serverName = server;
    debugs(83, 7, "SNI server name: " << serverName);
#endif

#if !defined(OPENSSL_NO_COMP)
    if (ssl->session->compress_meth)
        compressMethod = ssl->session->compress_meth;
    else if (sslVersion >= 3) //if it is 3 or newer version then compression is disabled
#endif
        compressMethod = 0;
    debugs(83, 7, "SSL compression: " << compressMethod);

    STACK_OF(SSL_CIPHER) * ciphers = NULL;
    if (ssl->server)
        ciphers = ssl->session->ciphers;
    else
        ciphers = ssl->cipher_list;
    if (ciphers) {
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
            SSL_CIPHER *c = sk_SSL_CIPHER_value(ciphers, i);
            if (c != NULL) {
                if (!clientRequestedCiphers.empty())
                    clientRequestedCiphers.append(":");
                clientRequestedCiphers.append(c->name);
            }
        }
    }
    debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

    if (sslVersion >=3 && ssl->s3 && ssl->s3->client_random[0]) {
        memcpy(client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE);
    }

#if 0 /* XXX: OpenSSL 0.9.8k lacks at least some of these tlsext_* fields */
    //The following extracted for logging purpuses:
    // TLSEXT_TYPE_ec_point_formats
    unsigned char *p;
    int len;
    if (ssl->server) {
        p = ssl->session->tlsext_ecpointformatlist;
        len = ssl->session->tlsext_ecpointformatlist_length;
    } else {
        p = ssl->tlsext_ecpointformatlist;
        len = ssl->tlsext_ecpointformatlist_length;
    }
    if (p) {
        ecPointFormatList = objToString(p, len);
        debugs(83, 7, "tlsExtension ecPointFormatList of length " << len << " :" << ecPointFormatList);
    }

    // TLSEXT_TYPE_elliptic_curves
    if (ssl->server) {
        p = ssl->session->tlsext_ellipticcurvelist;
        len = ssl->session->tlsext_ellipticcurvelist_length;
    } else {
        p = ssl->tlsext_ellipticcurvelist;
        len = ssl->tlsext_ellipticcurvelist_length;
    }
    if (p) {
        ellipticCurves = objToString(p, len);
        debugs(83, 7, "tlsExtension ellipticCurveList of length " <<  len <<" :" << ellipticCurves);
    }
    // TLSEXT_TYPE_opaque_prf_input
    p = NULL;
    if (ssl->server) {
        if (ssl->s3 &&  ssl->s3->client_opaque_prf_input) {
            p = (unsigned char *)ssl->s3->client_opaque_prf_input;
            len = ssl->s3->client_opaque_prf_input_len;
        }
    } else {
        p = (unsigned char *)ssl->tlsext_opaque_prf_input;
        len = ssl->tlsext_opaque_prf_input_len;
    }
    if (p) {
        debugs(83, 7, "tlsExtension client-opaque-prf-input of length " << len);
        opaquePrf = objToString(p, len);
    }
#endif
    initialized_ = true;
    return true;
}

int
Ssl::Bio::sslFeatures::parseMsgHead(const MemBuf &buf)
{
    const unsigned char *head = (const unsigned char *)buf.content();
    const char *s = objToString(head, buf.contentSize());
    debugs(83, 7, "SSL Header: " << s);
    if (buf.contentSize() < 5)
        return 0;

    if (helloMsgSize > 0)
        return helloMsgSize;

    // Check for SSLPlaintext/TLSPlaintext record
    // RFC6101 section 5.2.1
    // RFC5246 section 6.2.1
    if (head[0] == 0x16) {
        debugs(83, 7, "SSL version 3 handshake message");
        // The SSL version exist in the 2nd and 3rd bytes
        sslVersion = (head[1] << 8) | head[2];
        debugs(83, 7, "SSL Version :" << std::hex << std::setw(8) << std::setfill('0') << sslVersion);
        // The hello message size exist in 4th and 5th bytes
        helloMsgSize = (head[3] << 8) + head[4];
        debugs(83, 7, "SSL Header Size: " << helloMsgSize);
        helloMsgSize +=5;
    } else if ((head[0] & 0x80) && head[2] == 0x01 && head[3] == 0x03) {
        debugs(83, 7, "SSL version 2 handshake message with v3 support");
        sslVersion = (head[3] << 8) | head[4];
        debugs(83, 7, "SSL Version :" << std::hex << std::setw(8) << std::setfill('0') << sslVersion);
        // The hello message size exist in 2nd byte
        helloMsgSize = head[1];
        helloMsgSize +=2;
    } else {
        debugs(83, 7, "Not an SSL acceptable handshake message (SSLv2 message?)");
        return (helloMsgSize = -1);
    }

    // Set object as initialized. Even if we did not full parsing yet
    // The basic features, like the SSL version is set
    initialized_ = true;
    return helloMsgSize;
}

bool
Ssl::Bio::sslFeatures::checkForCcsOrNst(const unsigned char *msg, size_t size)
{
    while (size > 5) {
        const int msgType = msg[0];
        const int msgSslVersion = (msg[1] << 8) | msg[2];
        debugs(83, 7, "SSL Message Version :" << std::hex << std::setw(8) << std::setfill('0') << msgSslVersion);
        // Check for Change Cipher Spec message
        // RFC5246 section 6.2.1
        if (msgType == 0x14) {// Change Cipher Spec message found
            debugs(83, 7, "SSL  Change Cipher Spec message found");
            return true;
        }
        // Check for New Session Ticket message
        // RFC5077 section 3.3
        if (msgType == 0x04) {// New Session Ticket message found
            debugs(83, 7, "TLS  New Session Ticket message found");
            return true;
        }
        // The hello message size exist in 4th and 5th bytes
        size_t msgLength = (msg[3] << 8) + msg[4];
        debugs(83, 7, "SSL Message Size: " << msgLength);
        msgLength += 5;

        if (msgLength <= size) {
            msg += msgLength;
            size -= msgLength;
        } else
            size = 0;
    }
    return false;
}

bool
Ssl::Bio::sslFeatures::get(const MemBuf &buf, bool record)
{
    int msgSize;
    if ((msgSize = parseMsgHead(buf)) <= 0) {
        debugs(83, 7, "Not a known SSL handshake message");
        return false;
    }

    if (msgSize > buf.contentSize()) {
        debugs(83, 2, "Partial SSL handshake message, can not parse!");
        return false;
    }

    if (record) {
        helloMessage.clear();
        helloMessage.append(buf.content(), buf.contentSize());
    }

    const unsigned char *msg = (const unsigned char *)buf.content();
    if (msg[0] & 0x80)
        return parseV23Hello(msg, (size_t)msgSize);
    else {
        // Hello messages require 5 bytes header + 1 byte Msg type + 3 bytes for Msg size
        if (buf.contentSize() < 9)
            return false;

        // Check for the Handshake/Message type
        // The type 2 is a ServerHello, the type 1 is a ClientHello
        // RFC5246 section 7.4
        if (msg[5] == 0x2) { // ServerHello message
            if (parseV3ServerHello(msg, (size_t)msgSize)) {
                hasCcsOrNst = checkForCcsOrNst(msg + msgSize,  buf.contentSize() - msgSize);
                return true;
            }
        } else if (msg[5] == 0x1) // ClientHello message,
            return parseV3Hello(msg, (size_t)msgSize);
    }

    return false;
}

bool
Ssl::Bio::sslFeatures::parseV3ServerHello(const unsigned char *messageContainer, size_t messageContainerSize)
{
    // Parse a ServerHello Handshake message
    // RFC5246 section 7.4, 7.4.1.3
    // The ServerHello starts at messageContainer + 5
    const unsigned char *serverHello = messageContainer + 5;

    // The Length field (bytes 1-3) plus 4 bytes of the serverHello message header (1 handshake type + 3 hello length)
    const size_t helloSize = ((serverHello[1] << 16) | (serverHello[2] << 8) | serverHello[3]) + 4;
    debugs(83, 7, "ServerHello message size: " << helloSize);
    if (helloSize > messageContainerSize) {
        debugs(83, 2, "ServerHello parse error");
        return false;
    }

    // helloSize should be at least 38 bytes long:
    // (SSL Version + Random + SessionId Length + Cipher Suite + Compression Method)
    if (helloSize < 38) {
        debugs(83, 2, "Too short ServerHello message");
        return false;
    }

    debugs(83, 7, "Get fake features from v3 ServerHello message.");
    // Get the correct version of the sub-hello message
    sslVersion = (serverHello[4] << 8) | serverHello[5];
    // At the position 38 (HelloHeader (6bytes) + SSL3_RANDOM_SIZE (32bytes))
    const size_t sessIdLen = static_cast<size_t>(serverHello[38]);
    debugs(83, 7, "Session ID Length: " <<  sessIdLen);

    // The size should be enough to hold at least the following
    // 4 (hello header)
    // + 2 (SSL Version) + 32 (random) + 1 (sessionId length)
    // + sessIdLength + 2 (cipher suite) + 1 (compression method)
    // = 42 + sessIdLength
    if (42 + sessIdLen > helloSize) {
        debugs(83, 2, "ciphers length parse error");
        return false;
    }

    // The sessionID stored at 39 position, after sessionID length field
    sessionId.assign(reinterpret_cast<const char *>(serverHello + 39), sessIdLen);

    // Check if there are extensions in hello message
    // RFC5246 section 7.4.1.4
    if (helloSize > 42 + sessIdLen + 2) {
        // 42 + sessIdLen
        const unsigned char *pToExtensions = serverHello + 42 + sessIdLen;
        const size_t extensionsLen = (pToExtensions[0] << 8) | pToExtensions[1];
        // Check if the hello size can hold extensions
        if (42 + 2 + sessIdLen + extensionsLen > helloSize ) {
            debugs(83, 2, "Extensions length parse error");
            return false;
        }

        pToExtensions += 2;
        const unsigned char *ext = pToExtensions;
        while (ext + 4 <= pToExtensions + extensionsLen) {
            const size_t extType = (ext[0] << 8) | ext[1];
            ext += 2;
            const size_t extLen = (ext[0] << 8) | ext[1];
            ext += 2;
            debugs(83, 7, "TLS Extension: " << std::hex << extType << " of size:" << extLen);
            // SessionTicket TLS Extension, RFC5077 section 3.2
            if (extType == 0x23) {
                tlsTicketsExtension = true;
            }
            ext += extLen;
        }
    }
    return true;
}

bool
Ssl::Bio::sslFeatures::parseV3Hello(const unsigned char *messageContainer, size_t messageContainerSize)
{
    // Parse a ClientHello Handshake message
    // RFC5246 section 7.4, 7.4.1.2
    // The ClientHello starts at messageContainer + 5
    const unsigned char * clientHello = messageContainer + 5;

    debugs(83, 7, "Get fake features from v3 ClientHello message.");
    // The Length field (bytes 1-3) plus 4 bytes of the clientHello message header (1 handshake type + 3 hello length)
    const size_t helloSize = ((clientHello[1] << 16) | (clientHello[2] << 8) | clientHello[3]) + 4;
    debugs(83, 7, "ClientHello message size: " << helloSize);
    if (helloSize > messageContainerSize) {
        debugs(83, 2, "ClientHello parse error");
        return false;
    }

    // helloSize should be at least 38 bytes long:
    // (SSL Version(2) + Random(32) + SessionId Length(1) + Cipher Suite Length(2) + Compression Method Length(1))
    if (helloSize < 38) {
        debugs(83, 2, "Too short ClientHello message");
        return false;
    }

    //For SSLv3 or TLSv1.* protocols we can get some more informations
    if (messageContainer[1] != 0x3 || clientHello[0] != 0x1 /*HELLO A message*/) {
        debugs(83, 2, "Not an SSLv3/TLSv1.x client hello message, stop parsing here");
        return true;
    }

    // Get the correct version of the sub-hello message
    sslVersion = (clientHello[4] << 8) | clientHello[5];
    //Get Client Random number. It starts on the position 6 of clientHello message
    memcpy(client_random, clientHello + 6, SSL3_RANDOM_SIZE);
    debugs(83, 7, "Client random: " <<  objToString(client_random, SSL3_RANDOM_SIZE));

    // At the position 38 (6+SSL3_RANDOM_SIZE)
    const size_t sessIDLen = static_cast<size_t>(clientHello[38]);
    debugs(83, 7, "Session ID Length: " <<  sessIDLen);

    // The helloSize should be enough to hold at least the following
    // 1 handshake type + 3 hello Length
    // + 2 (SSL Version) + 32 (random) + 1 (sessionId length)
    // + sessIdLength + 2 (cipher suite length) + 1 (compression method length)
    // = 42 + sessIdLength
    if (42 + sessIDLen > helloSize) {
        debugs(83, 2, "Session ID length parse error");
        return false;
    }

    // The sessionID stored art 39 position, after sessionID length field
    sessionId.assign(reinterpret_cast<const char *>(clientHello + 39), sessIDLen);

    //Ciphers list. It is stored after the Session ID.
    // It is a variable-length vector(RFC5246 section 4.3)
    const unsigned char *ciphers = clientHello + 39 + sessIDLen;
    const size_t ciphersLen = (ciphers[0] << 8) | ciphers[1];
    if (42 + sessIDLen + ciphersLen > helloSize) {
        debugs(83, 2, "ciphers length parse error");
        return false;
    }

    ciphers += 2;
    if (ciphersLen) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        const SSL_METHOD *method = TLS_method();
#else
        const SSL_METHOD *method = SSLv23_method();
#endif
        for (size_t i = 0; i < ciphersLen; i += 2) {
            // each cipher in v3/tls  HELLO message is of size 2
            const SSL_CIPHER *c = method->get_cipher_by_char((ciphers + i));
            if (c != NULL) {
                if (!clientRequestedCiphers.empty())
                    clientRequestedCiphers.append(":");
                clientRequestedCiphers.append(c->name);
            } else
                unknownCiphers = true;
        }
    }
    debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

    // Compression field: 1 bytes the number of compression methods and
    // 1 byte for each compression method
    const unsigned char *compression = ciphers + ciphersLen;
    if (compression[0] > 1)
        compressMethod = 1;
    else
        compressMethod = 0;
    debugs(83, 7, "SSL compression methods number: " << static_cast<int>(compression[0]));

    // Parse Extensions, RFC5246 section 7.4.1.4
    const unsigned char *pToExtensions = compression + 1 + static_cast<int>(compression[0]);
    if ((size_t)((pToExtensions - clientHello) + 2) < helloSize) {
        const size_t extensionsLen = (pToExtensions[0] << 8) | pToExtensions[1];
        if ((pToExtensions - clientHello) + 2 + extensionsLen > helloSize) {
            debugs(83, 2, "Extensions length parse error");
            return false;
        }

        pToExtensions += 2;
        const unsigned char *ext = pToExtensions;
        while (ext + 4 <= pToExtensions + extensionsLen) {
            const size_t extType = (ext[0] << 8) | ext[1];
            ext += 2;
            const size_t extLen = (ext[0] << 8) | ext[1];
            ext += 2;
            debugs(83, 7, "TLS Extension: " << std::hex << extType << " of size:" << extLen);

            if (ext + extLen > pToExtensions + extensionsLen) {
                debugs(83, 2, "Extension " << std::hex << extType << " length parser error");
                return false;
            }

            //The SNI extension has the type 0 (extType == 0)
            // RFC6066 sections 3, 10.2
            // The two first bytes indicates the length of the SNI data (should be extLen-2)
            // The next byte is the hostname type, it should be '0' for normal hostname (ext[2] == 0)
            // The 3rd and 4th bytes are the length of the hostname
            if (extType == 0 && ext[2] == 0) {
                const size_t hostLen = (ext[3] << 8) | ext[4];
                if (hostLen < extLen)
                    serverName.assign(reinterpret_cast<const char *>(ext+5), hostLen);
                debugs(83, 7, "Found server name: " << serverName);
            } else if (extType == 15 && ext[0] != 0) {
                // The heartBeats are the type 15, RFC6520
                doHeartBeats = true;
            } else if (extType == 0x23) {
                //SessionTicket TLS Extension RFC5077
                tlsTicketsExtension = true;
                if (extLen != 0)
                    hasTlsTicket = true;
            } else if (extType == 0x05) {
                // RFC6066 sections 8, 10.2
                tlsStatusRequest = true;
            } else if (extType == 0x3374) {
                // detected TLS next protocol negotiate extension
            } else if (extType == 0x10) {
                // Application-Layer Protocol Negotiation Extension, RFC7301
                const size_t listLen = (ext[0] << 8) | ext[1];
                if (listLen < extLen)
                    tlsAppLayerProtoNeg.assign(reinterpret_cast<const char *>(ext+5), listLen);
            } else
                extensions.push_back(extType);

            ext += extLen;
        }
    }
    return true;
}

bool
Ssl::Bio::sslFeatures::parseV23Hello(const unsigned char *hello, size_t size)
{
    debugs(83, 7, "Get fake features from v23 ClientHello message.");
    if (size < 7)
        return false;
    //Ciphers list. It is stored after the Session ID.
    const unsigned int ciphersLen = (hello[5] << 8) | hello[6];
    const unsigned char *ciphers = hello + 11;

    if (size < ciphersLen + 11)
        return false;

    if (ciphersLen) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
        const SSL_METHOD *method = TLS_method();
#else
        const SSL_METHOD *method = SSLv23_method();
#endif
        for (unsigned int i = 0; i < ciphersLen; i += 3) {
            // The v2 hello messages cipher has 3 bytes.
            // The v2 cipher has the first byte not null
            // Because we are going to sent only v3 message we
            // are ignoring these ciphers
            if (ciphers[i] != 0)
                continue;
            const SSL_CIPHER *c = method->get_cipher_by_char((ciphers + i + 1));
            if (c != NULL) {
                if (!clientRequestedCiphers.empty())
                    clientRequestedCiphers.append(":");
                clientRequestedCiphers.append(c->name);
            }
        }
    }
    debugs(83, 7, "Ciphers requested by client: " << clientRequestedCiphers);

    const unsigned int sessionIdLength = (hello[7] << 8) | hello[8];
    debugs(83, 7, "SessionID length: " << sessionIdLength);
    // SessionID starts at: hello+11+ciphersLen
    if (sessionIdLength)
        sessionId.assign((const char *)(hello + 11 + ciphersLen), sessionIdLength);

    const unsigned int challengeLength = (hello[5] << 9) | hello[10];
    debugs(83, 7, "Challenge Length: " << challengeLength);
    //challenge starts at: hello+11+ciphersLen+sessionIdLength

    compressMethod = 0;
    return true;
}

void
Ssl::Bio::sslFeatures::applyToSSL(SSL *ssl, Ssl::BumpMode bumpMode) const
{
    // To increase the possibility for bumping after peek mode selection or
    // splicing after stare mode selection it is good to set the
    // SSL protocol version.
    // The SSL_set_ssl_method is not the correct method because it will strict
    // SSL version which can be used to the SSL version used for client hello message.
    // For example will prevent comunnicating with a tls1.0 server if the
    // client sent and tlsv1.2 Hello message.
    //SSL_set_ssl_method(ssl, Ssl::method(features.toSquidSSLVersion()));
#if defined(TLSEXT_NAMETYPE_host_name)
    if (!serverName.isEmpty()) {
        SSL_set_tlsext_host_name(ssl, serverName.c_str());
    }
#endif
    if (!clientRequestedCiphers.empty())
        SSL_set_cipher_list(ssl, clientRequestedCiphers.c_str());
#if defined(SSL_OP_NO_COMPRESSION) /* XXX: OpenSSL 0.9.8k lacks SSL_OP_NO_COMPRESSION */
    if (compressMethod == 0)
        SSL_set_options(ssl, SSL_OP_NO_COMPRESSION);
#endif

#if defined(TLSEXT_STATUSTYPE_ocsp)
    if (tlsStatusRequest)
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
#endif

#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
    if (!tlsAppLayerProtoNeg.isEmpty()) {
        if (bumpMode == Ssl::bumpPeek)
            SSL_set_alpn_protos(ssl, (const unsigned char*)tlsAppLayerProtoNeg.rawContent(), tlsAppLayerProtoNeg.length());
        else {
            static const unsigned char supported_protos[] = {8, 'h','t','t', 'p', '/', '1', '.', '1'};
            SSL_set_alpn_protos(ssl, supported_protos, sizeof(supported_protos));
        }
    }
#endif
}

std::ostream &
Ssl::Bio::sslFeatures::print(std::ostream &os) const
{
    static std::string buf;
    // TODO: Also print missing features like the HeartBeats and AppLayerProtoNeg
    return os << "v" << sslVersion <<
           " SNI:" << (serverName.isEmpty() ? SBuf("-") : serverName) <<
           " comp:" << compressMethod <<
           " Ciphers:" << clientRequestedCiphers <<
           " Random:" << objToString(client_random, SSL3_RANDOM_SIZE) <<
           " ecPointFormats:" << ecPointFormatList <<
           " ec:" << ellipticCurves <<
           " opaquePrf:" << opaquePrf;
}

#endif /* USE_SSL */

