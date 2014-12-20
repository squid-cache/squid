/*
 * Copyright (C) 1996-2014 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "fatal.h"

/* Stub File for the ssl/libsslutil.la convenience library */

#define STUB_BASE "ssl/libsslutil.la"

#define STUB { fatal(STUB_BASE " required."); }
#define STUB_RETVAL(x) { fatal(STUB_BASE " required."); return (x); }
#define STUB_RETREF(x) { fatal(STUB_BASE " required."); static x v; return v; }
#define STUB_RETREF2(x,y) { fatal(STUB_BASE " required."); static x v((y)); return v; }

#include "ssl/crtd_message.h"
Ssl::CrtdMessage::CrtdMessage() STUB
Ssl::CrtdMessage::ParseResult Ssl::CrtdMessage::parse(const char * buffer, size_t len) STUB_RETVAL(ERROR)
std::string const & Ssl::CrtdMessage::getBody() const STUB_RETREF(std::string)
std::string const & Ssl::CrtdMessage::getCode() const STUB_RETREF(std::string)
void Ssl::CrtdMessage::setBody(std::string const & aBody) STUB
void Ssl::CrtdMessage::setCode(std::string const & aCode) STUB
std::string Ssl::CrtdMessage::compose() const STUB_RETREF(std::string)
void Ssl::CrtdMessage::clear() STUB
void Ssl::CrtdMessage::parseBody(BodyParams & map, std::string & other_part) const STUB
void Ssl::CrtdMessage::composeBody(BodyParams const & map, std::string const & other_part) STUB

#include "ssl/gadgets.h"
X509_REQ * Ssl::createNewX509Request(EVP_PKEY_Pointer const & pkey, const char * hostname) STUB_RETVAL(NULL)
bool Ssl::writeCertAndPrivateKeyToMemory(X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey, std::string & bufferToWrite) STUB_RETVAL(false)
bool Ssl::writeCertAndPrivateKeyToFile(X509_Pointer const & cert, EVP_PKEY_Pointer const & pkey, char const * filename) STUB_RETVAL(false)
bool Ssl::readCertAndPrivateKeyFromMemory(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, char const * bufferToRead) STUB_RETVAL(false)
X509 * Ssl::signRequest(X509_REQ_Pointer const & request, X509_Pointer const & x509, EVP_PKEY_Pointer const & pkey, ASN1_TIME * timeNotAfter, BIGNUM const * serial) STUB_RETVAL(NULL)
bool Ssl::generateSslCertificateAndPrivateKey(char const *host, X509_Pointer const & signedX509, EVP_PKEY_Pointer const & signedPkey, X509_Pointer & cert, EVP_PKEY_Pointer & pkey, BIGNUM const* serial) STUB_RETVAL(false)
void Ssl::readCertAndPrivateKeyFromFiles(X509_Pointer & cert, EVP_PKEY_Pointer & pkey, char const * certFilename, char const * keyFilename) STUB
bool Ssl::sslDateIsInTheFuture(char const * date) STUB_RETVAL(false)

#include "ssl/helper.h"
Ssl::Helper * Ssl::Helper::GetInstance() STUB_RETVAL(NULL)
void Ssl::Helper::Init() STUB
void Ssl::Helper::Shutdown() STUB
void Ssl::Helper::sslSubmit(Ssl::CrtdMessage const & message, HLPCB * callback, void *data) STUB

