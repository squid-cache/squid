/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#if USE_OPENSSL

#include "fatal.h"

/* Stub File for the ssl/libsslutil.la convenience library */

#define STUB_API "ssl/libsslutil.la"
#include "tests/STUB.h"

#include "ssl/crtd_message.h"
namespace Ssl
{
CrtdMessage::CrtdMessage(MessageKind) {STUB}
CrtdMessage::ParseResult CrtdMessage::parse(const char *, size_t) STUB_RETVAL(ERROR)
std::string const & CrtdMessage::getBody() const STUB_RETREF(std::string)
std::string const & CrtdMessage::getCode() const STUB_RETREF(std::string)
void CrtdMessage::setBody(std::string const &) STUB
void CrtdMessage::setCode(std::string const &) STUB
std::string CrtdMessage::compose() const STUB_RETVAL(std::string())
void CrtdMessage::clear() STUB
void CrtdMessage::parseBody(BodyParams &, std::string &) const STUB
void CrtdMessage::composeBody(BodyParams const &, std::string const &) STUB
bool CrtdMessage::parseRequest(Security::CertificateProperties &, std::string &) STUB_RETVAL(false)
void CrtdMessage::composeRequest(Security::CertificateProperties const &) STUB
const std::string CrtdMessage::code_new_certificate;
const std::string CrtdMessage::param_host;
const std::string CrtdMessage::param_SetValidAfter;
const std::string CrtdMessage::param_SetValidBefore;
const std::string CrtdMessage::param_SetCommonName;
const std::string CrtdMessage::param_Sign;
const std::string CrtdMessage::param_SignHash;
} // namespace Ssl

#include "ssl/gadgets.h"
namespace Ssl
{
X509_REQ *createNewX509Request(Security::PrivateKeyPointer const &, const char *) STUB_RETVAL(nullptr)
bool writeCertAndPrivateKeyToMemory(Security::CertPointer const &, Security::PrivateKeyPointer const &, std::string &) STUB_RETVAL(false)
bool writeCertAndPrivateKeyToFile(Security::CertPointer const &, Security::PrivateKeyPointer const &, char const *) STUB_RETVAL(false)
bool readCertAndPrivateKeyFromMemory(Security::CertPointer &, Security::PrivateKeyPointer &, char const *) STUB_RETVAL(false)
X509 *signRequest(X509_REQ_Pointer const &, Security::CertPointer const &, Security::PrivateKeyPointer const &, ASN1_TIME *, BIGNUM const *) STUB_RETVAL(nullptr)
bool generateSslCertificateAndPrivateKey(char const *, Security::CertPointer const &, Security::PrivateKeyPointer const &, Security::CertPointer &, Security::PrivateKeyPointer &, BIGNUM const *) STUB_RETVAL(false)
void readCertAndPrivateKeyFromFiles(Security::CertPointer &, Security::PrivateKeyPointer &, char const *, char const *) STUB
bool sslDateIsInTheFuture(char const *) STUB_RETVAL(false)
} // namespace Ssl

#endif /* USE_OPENSSL */

