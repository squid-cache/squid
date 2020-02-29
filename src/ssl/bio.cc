/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
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
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "ip/Address.h"
#include "parser/BinaryTokenizer.h"
#include "SquidTime.h"
#include "ssl/bio.h"

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

#if HAVE_LIBCRYPTO_BIO_METH_NEW
static BIO_METHOD *SquidMethods = nullptr;
#else
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
#endif

BIO *
Ssl::Bio::Create(const int fd, Security::Io::Type type)
{
#if HAVE_LIBCRYPTO_BIO_METH_NEW
    if (!SquidMethods) {
        SquidMethods = BIO_meth_new(BIO_TYPE_SOCKET, "squid");
        BIO_meth_set_write(SquidMethods, squid_bio_write);
        BIO_meth_set_read(SquidMethods, squid_bio_read);
        BIO_meth_set_puts(SquidMethods, squid_bio_puts);
        BIO_meth_set_gets(SquidMethods, NULL);
        BIO_meth_set_ctrl(SquidMethods, squid_bio_ctrl);
        BIO_meth_set_create(SquidMethods, squid_bio_create);
        BIO_meth_set_destroy(SquidMethods, squid_bio_destroy);
    }
    BIO_METHOD *useMethod = SquidMethods;
#else
    BIO_METHOD *useMethod = &SquidMethods;
#endif

    if (BIO *bio = BIO_new(useMethod)) {
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

Ssl::ClientBio::ClientBio(const int anFd):
    Bio(anFd),
    holdRead_(false),
    holdWrite_(false),
    helloSize(0),
    abortReason(nullptr)
{
    renegotiations.configure(10*1000);
}

void
Ssl::ClientBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
    // detect client-initiated renegotiations DoS (CVE-2011-1473)
    if (where & SSL_CB_HANDSHAKE_START) {
        const int reneg = renegotiations.count(1);

        if (abortReason)
            return; // already decided and informed the admin

        if (reneg > RenegotiationsLimit) {
            abortReason = "renegotiate requests flood";
            debugs(83, DBG_IMPORTANT, "Terminating TLS connection [from " << fd_table[fd_].ipaddr << "] due to " << abortReason << ". This connection received " <<
                   reneg << " renegotiate requests in the last " <<
                   RenegotiationsWindow << " seconds (and " <<
                   renegotiations.remembered() << " requests total).");
        }
    }
}

int
Ssl::ClientBio::write(const char *buf, int size, BIO *table)
{
    if (abortReason) {
        debugs(83, 3, "BIO on FD " << fd_ << " is aborted");
        BIO_clear_retry_flags(table);
        return -1;
    }

    if (holdWrite_) {
        BIO_set_retry_write(table);
        return 0;
    }

    return Ssl::Bio::write(buf, size, table);
}

int
Ssl::ClientBio::read(char *buf, int size, BIO *table)
{
    if (abortReason) {
        debugs(83, 3, "BIO on FD " << fd_ << " is aborted");
        BIO_clear_retry_flags(table);
        return -1;
    }

    if (holdRead_) {
        debugs(83, 7, "Hold flag is set, retry latter. (Hold " << size << "bytes)");
        BIO_set_retry_read(table);
        return -1;
    }

    if (!rbuf.isEmpty()) {
        int bytes = (size <= (int)rbuf.length() ? size : rbuf.length());
        memcpy(buf, rbuf.rawContent(), bytes);
        rbuf.consume(bytes);
        return bytes;
    } else
        return Ssl::Bio::read(buf, size, table);

    return -1;
}

Ssl::ServerBio::ServerBio(const int anFd):
    Bio(anFd),
    helloMsgSize(0),
    helloBuild(false),
    allowSplice(false),
    allowBump(false),
    holdWrite_(false),
    holdRead_(true),
    record_(false),
    parsedHandshake(false),
    parseError(false),
    bumpMode_(bumpNone),
    rbufConsumePos(0)
{
}

void
Ssl::ServerBio::stateChanged(const SSL *ssl, int where, int ret)
{
    Ssl::Bio::stateChanged(ssl, where, ret);
}

void
Ssl::ServerBio::setClientFeatures(Security::TlsDetails::Pointer const &details, SBuf const &aHello)
{
    clientTlsDetails = details;
    clientSentHello = aHello;
};

int
Ssl::ServerBio::read(char *buf, int size, BIO *table)
{
    if (parsedHandshake) // done parsing TLS Hello
        return readAndGive(buf, size, table);
    else
        return readAndParse(buf, size, table);
}

/// Read and give everything to OpenSSL.
int
Ssl::ServerBio::readAndGive(char *buf, const int size, BIO *table)
{
    // If we have unused buffered bytes, give those bytes to OpenSSL now,
    // before reading more. TODO: Read if we have buffered less than size?
    if (rbufConsumePos < rbuf.length())
        return giveBuffered(buf, size);

    if (record_) {
        const int result = readAndBuffer(table);
        if (result <= 0)
            return result;
        return giveBuffered(buf, size);
    }

    return Ssl::Bio::read(buf, size, table);
}

/// Read and give everything to our parser.
/// When/if parsing is finished (successfully or not), start giving to OpenSSL.
int
Ssl::ServerBio::readAndParse(char *buf, const int size, BIO *table)
{
    const int result = readAndBuffer(table);
    if (result <= 0)
        return result;

    try {
        if (!parser_.parseHello(rbuf)) {
            // need more data to finish parsing
            BIO_set_retry_read(table);
            return -1;
        }
        parsedHandshake = true; // done parsing (successfully)
    }
    catch (const std::exception &ex) {
        debugs(83, 2, "parsing error on FD " << fd_ << ": " << ex.what());
        parsedHandshake = true; // done parsing (due to an error)
        parseError = true;
    }

    if (holdRead_) {
        debugs(83, 7, "Hold flag is set, retry latter. (Hold " << size << "bytes)");
        BIO_set_retry_read(table);
        return -1;
    }

    return giveBuffered(buf, size);
}

/// Reads more data into the read buffer. Returns either the number of bytes
/// read or, on errors (including "try again" errors), a negative number.
int
Ssl::ServerBio::readAndBuffer(BIO *table)
{
    char *space = rbuf.rawAppendStart(SQUID_TCP_SO_RCVBUF);
    const int result = Ssl::Bio::read(space, SQUID_TCP_SO_RCVBUF, table);
    if (result <= 0)
        return result;

    rbuf.rawAppendFinish(space, result);
    return result;
}

/// give previously buffered bytes to OpenSSL
/// returns the number of bytes given
int
Ssl::ServerBio::giveBuffered(char *buf, const int size)
{
    if (rbuf.length() <= rbufConsumePos)
        return -1; // buffered nothing yet

    const int unsent = rbuf.length() - rbufConsumePos;
    const int bytes = (size <= unsent ? size : unsent);
    memcpy(buf, rbuf.rawContent() + rbufConsumePos, bytes);
    rbufConsumePos += bytes;
    debugs(83, 7, bytes << "<=" << size << " bytes to OpenSSL");
    return bytes;
}

// This function makes the required checks to examine if the client hello
// message is compatible with the features provided by OpenSSL toolkit.
// If the features are compatible and can be supported it tries to rewrite SSL
// structure members, to replace the hello message created by openSSL, with the
// web client SSL hello message.
// This is mostly possible in the cases where the web client uses openSSL
// library similar with this one used by squid.
static bool
adjustSSL(SSL *ssl, Security::TlsDetails::Pointer const &details, SBuf &helloMessage)
{
#if SQUID_USE_OPENSSL_HELLO_OVERWRITE_HACK
    if (!details)
        return false;

    if (!ssl->s3) {
        debugs(83, 5, "No SSLv3 data found!");
        return false;
    }

    // If the client supports compression but our context does not support
    // we can not adjust.
#if !defined(OPENSSL_NO_COMP)
    const bool requireCompression = (details->compressionSupported && ssl->ctx->comp_methods == nullptr);
#else
    const bool requireCompression = details->compressionSupported;
#endif
    if (requireCompression) {
        debugs(83, 5, "Client Hello Data supports compression, but we do not!");
        return false;
    }

#if !defined(SSL_TLSEXT_HB_ENABLED)
    if (details->doHeartBeats) {
        debugs(83, 5, "Client Hello Data supports HeartBeats but we do not support!");
        return false;
    }
#endif

    if (details->unsupportedExtensions) {
        debugs(83, 5, "Client Hello contains extensions that we do not support!");
        return false;
    }

    SSL3_BUFFER *wb=&(ssl->s3->wbuf);
    if (wb->len < (size_t)helloMessage.length()) {
        debugs(83, 5, "Client Hello exceeds OpenSSL buffer: " << helloMessage.length() << " >= " << wb->len);
        return false;
    }

    /* Check whether all on-the-wire ciphers are supported by OpenSSL. */

    const auto &wireCiphers = details->ciphers;
    Security::TlsDetails::Ciphers::size_type ciphersToFind = wireCiphers.size();

    // RFC 5746: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV is not a true cipher suite".
    // It is commonly seen on the wire, including in from-OpenSSL traffic, but
    // SSL_get_ciphers() does not return this _pseudo_ cipher suite in my tests.
    // If OpenSSL supports scsvCipher, we count it (at most once) further below.
#if defined(TLSEXT_TYPE_renegotiate)
    // the 0x00FFFF mask converts 3-byte OpenSSL cipher to our 2-byte cipher
    const uint16_t scsvCipher = SSL3_CK_SCSV & 0x00FFFF;
#else
    const uint16_t scsvCipher = 0;
#endif

    STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(ssl);
    const int supportedCipherCount = sk_SSL_CIPHER_num(cipher_stack);
    for (int idx = 0; idx < supportedCipherCount && ciphersToFind > 0; ++idx) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(cipher_stack, idx);
        const auto id = SSL_CIPHER_get_id(cipher) & 0x00FFFF;
        if (wireCiphers.find(id) != wireCiphers.end() && (!scsvCipher || id != scsvCipher))
            --ciphersToFind;
    }

    if (ciphersToFind > 0 && scsvCipher && wireCiphers.find(scsvCipher) != wireCiphers.end())
        --ciphersToFind;

    if (ciphersToFind > 0) {
        // TODO: Add slowlyReportUnsupportedCiphers() to slowly find and report each of them
        debugs(83, 5, "Client Hello Data has " << ciphersToFind << " ciphers that we do not support!");
        return false;
    }

    debugs(83, 5, "OpenSSL SSL struct will be adjusted to mimic client hello data!");

    //Adjust ssl structure data.
    // We need to fix the random in SSL struct:
    if (details->clientRandom.length() == SSL3_RANDOM_SIZE)
        memcpy(ssl->s3->client_random, details->clientRandom.c_str(), SSL3_RANDOM_SIZE);
    memcpy(wb->buf, helloMessage.rawContent(), helloMessage.length());
    wb->left = helloMessage.length();

    size_t mainHelloSize = helloMessage.length() - 5;
    const char *mainHello = helloMessage.rawContent() + 5;
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
        debugs(83, 7, "postpone writing " << size << " bytes to SSL FD " << fd_);
        BIO_set_retry_write(table);
        return -1;
    }

    if (!helloBuild && (bumpMode_ == Ssl::bumpPeek || bumpMode_ == Ssl::bumpStare)) {
        // buf contains OpenSSL-generated ClientHello. We assume it has a
        // complete ClientHello and nothing else, but cannot fully verify
        // that quickly. We only verify that buf starts with a v3+ record
        // containing ClientHello.
        Must(size >= 2); // enough for version and content_type checks below
        Must(buf[1] >= 3); // record's version.major; determines buf[0] meaning
        Must(buf[0] == 22); // TLSPlaintext.content_type == handshake in v3+

        //Hello message is the first message we write to server
        assert(helloMsg.isEmpty());

        if (auto ssl = fd_table[fd_].ssl.get()) {
            if (bumpMode_ == Ssl::bumpPeek) {
                // we should not be here if we failed to parse the client-sent ClientHello
                Must(!clientSentHello.isEmpty());
                if (adjustSSL(ssl, clientTlsDetails, clientSentHello))
                    allowBump = true;
                allowSplice = true;
                // Replace OpenSSL-generated ClientHello with client-sent one.
                helloMsg.append(clientSentHello);
                debugs(83, 7,  "FD " << fd_ << ": Using client-sent ClientHello for peek mode");
            } else { /*Ssl::bumpStare*/
                allowBump = true;
                if (!clientSentHello.isEmpty() && adjustSSL(ssl, clientTlsDetails, clientSentHello)) {
                    allowSplice = true;
                    helloMsg.append(clientSentHello);
                    debugs(83, 7,  "FD " << fd_ << ": Using client-sent ClientHello for stare mode");
                }
            }
        }
        // if we did not use the client-sent ClientHello, then use the OpenSSL-generated one
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
    return parser_.resumingSession;
}

/// initializes BIO table after allocation
static int
squid_bio_create(BIO *bi)
{
#if !HAVE_LIBCRYPTO_BIO_GET_INIT
    bi->init = 0; // set when we store Bio object and socket fd (BIO_C_SET_FD)
    bi->num = 0;
    bi->flags = 0;
#else
    // No need to set more, openSSL initialize BIO memory to zero.
#endif

    BIO_set_data(bi, NULL);
    return 1;
}

/// cleans BIO table before deallocation
static int
squid_bio_destroy(BIO *table)
{
    delete static_cast<Ssl::Bio*>(BIO_get_data(table));
    BIO_set_data(table, NULL);
    return 1;
}

/// wrapper for Bio::write()
static int
squid_bio_write(BIO *table, const char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(BIO_get_data(table));
    assert(bio);
    return bio->write(buf, size, table);
}

/// wrapper for Bio::read()
static int
squid_bio_read(BIO *table, char *buf, int size)
{
    Ssl::Bio *bio = static_cast<Ssl::Bio*>(BIO_get_data(table));
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
        if (arg1 == Security::Io::BIO_TO_SERVER)
            bio = new Ssl::ServerBio(fd);
        else
            bio = new Ssl::ClientBio(fd);
        assert(!BIO_get_data(table));
        BIO_set_data(table, bio);
        BIO_set_init(table, 1);
        return 0;
    }

    case BIO_C_GET_FD:
        if (BIO_get_init(table)) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(BIO_get_data(table));
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
        if (BIO_get_init(table)) {
            Ssl::Bio *bio = static_cast<Ssl::Bio*>(BIO_get_data(table));
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
        if (Ssl::Bio *bio = static_cast<Ssl::Bio*>(BIO_get_data(table)))
            bio->stateChanged(ssl, where, ret);
    }
}

void
applyTlsDetailsToSSL(SSL *ssl, Security::TlsDetails::Pointer const &details, Ssl::BumpMode bumpMode)
{
    // To increase the possibility for bumping after peek mode selection or
    // splicing after stare mode selection it is good to set the
    // SSL protocol version.
    // The SSL_set_ssl_method is wrong here because it will restrict the
    // permitted transport version to be identical to the version used in the
    // ClientHello message.
    // For example will prevent comunnicating with a tls1.0 server if the
    // client sent and tlsv1.2 Hello message.
#if defined(TLSEXT_NAMETYPE_host_name)
    if (!details->serverName.isEmpty()) {
        SSL_set_tlsext_host_name(ssl, details->serverName.c_str());
    }
#endif

    if (!details->ciphers.empty()) {
        SBuf strCiphers;
        for (auto cipherId: details->ciphers) {
            unsigned char cbytes[3];
            cbytes[0] = (cipherId >> 8) & 0xFF;
            cbytes[1] = cipherId & 0xFF;
            cbytes[2] = 0;
            if (const auto c = SSL_CIPHER_find(ssl, cbytes)) {
                if (!strCiphers.isEmpty())
                    strCiphers.append(":");
                strCiphers.append(SSL_CIPHER_get_name(c));
            }
        }
        if (!strCiphers.isEmpty())
            SSL_set_cipher_list(ssl, strCiphers.c_str());
    }

#if defined(SSL_OP_NO_COMPRESSION) /* XXX: OpenSSL 0.9.8k lacks SSL_OP_NO_COMPRESSION */
    if (!details->compressionSupported)
        SSL_set_options(ssl, SSL_OP_NO_COMPRESSION);
#endif

#if defined(TLSEXT_STATUSTYPE_ocsp)
    if (details->tlsStatusRequest)
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
#endif

#if defined(TLSEXT_TYPE_application_layer_protocol_negotiation)
    if (!details->tlsAppLayerProtoNeg.isEmpty()) {
        if (bumpMode == Ssl::bumpPeek)
            SSL_set_alpn_protos(ssl, (const unsigned char*)details->tlsAppLayerProtoNeg.rawContent(), details->tlsAppLayerProtoNeg.length());
        else {
            static const unsigned char supported_protos[] = {8, 'h','t','t', 'p', '/', '1', '.', '1'};
            SSL_set_alpn_protos(ssl, supported_protos, sizeof(supported_protos));
        }
    }
#endif
}

#endif // USE_OPENSSL

