/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "fatal.h"

/* Unused (XXX) Stub File for the ssl/libsslutil.la convenience library */

#define STUB_API "ssl/libsslutil.la"
#include "tests/STUB.h"

#include "ssl/crtd_message.h"
Ssl::CrtdMessage::CrtdMessage() STUB
Ssl::CrtdMessage::ParseResult Ssl::CrtdMessage::parse(const char * buffer, size_t len) STUB_RETVAL(ERROR)
std::string const & Ssl::CrtdMessage::getBody() const STUB_RETREF(std::string)
std::string const & Ssl::CrtdMessage::getCode() const STUB_RETREF(std::string)
void Ssl::CrtdMessage::setBody(std::string const & aBody) STUB
void Ssl::CrtdMessage::setCode(std::string const & aCode) STUB
std::string Ssl::CrtdMessage::compose() const STUB_RETVAL(std::string())
void Ssl::CrtdMessage::clear() STUB
void Ssl::CrtdMessage::parseBody(BodyParams & map, std::string & other_part) const STUB
void Ssl::CrtdMessage::composeBody(BodyParams const & map, std::string const & other_part) STUB

#include "ssl/gadgets.h"
X509_REQ * Ssl::createNewX509Request(Security::PrivateKeyPointer const &, const char *) STUB_RETVAL(nullptr)
bool Ssl::writeCertAndPrivateKeyToMemory(Security::CertPointer const &, Security::PrivateKeyPointer const &, std::string &) STUB_RETVAL(false)
bool Ssl::writeCertAndPrivateKeyToFile(Security::CertPointer const &, Security::PrivateKeyPointer const &, char const *) STUB_RETVAL(false)
bool Ssl::readCertAndPrivateKeyFromMemory(Security::CertPointer &, Security::PrivateKeyPointer &, char const *) STUB_RETVAL(false)
X509 * Ssl::signRequest(X509_REQ_Pointer const &, Security::CertPointer const &, Security::PrivateKeyPointer const &, ASN1_TIME *, BIGNUM const *) STUB_RETVAL(nullptr)
bool Ssl::generateSslCertificateAndPrivateKey(char const *, Security::CertPointer const &, Security::PrivateKeyPointer const &, Security::CertPointer &, Security::PrivateKeyPointer &, BIGNUM const *) STUB_RETVAL(false)
void Ssl::readCertAndPrivateKeyFromFiles(Security::CertPointer &, Security::PrivateKeyPointer &, char const *, char const *) STUB
bool Ssl::sslDateIsInTheFuture(char const *) STUB_RETVAL(false)

#include "ssl/helper.h"
void Ssl::Helper::Init() STUB
void Ssl::Helper::Shutdown() STUB
void Ssl::Helper::Submit(Ssl::CrtdMessage const & message, HLPCB * callback, void *data) STUB

