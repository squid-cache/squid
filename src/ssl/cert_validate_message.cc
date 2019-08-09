/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "globals.h"
#include "helper.h"
#include "ssl/cert_validate_message.h"
#include "ssl/ErrorDetail.h"
#include "ssl/support.h"

void
Ssl::CertValidationMsg::composeRequest(CertValidationRequest const &vcert)
{
    body.clear();
    body += Ssl::CertValidationMsg::param_host + "=" + vcert.domainName;
    STACK_OF(X509) *peerCerts = static_cast<STACK_OF(X509) *>(SSL_get_ex_data(vcert.ssl, ssl_ex_index_ssl_cert_chain));

    if (const char *sslVersion = SSL_get_version(vcert.ssl))
        body += "\n" +  Ssl::CertValidationMsg::param_proto_version + "=" + sslVersion;

    if (const char *cipherName = SSL_CIPHER_get_name(SSL_get_current_cipher(vcert.ssl)))
        body += "\n" +  Ssl::CertValidationMsg::param_cipher + "=" + cipherName;

    if (!peerCerts)
        peerCerts = SSL_get_peer_cert_chain(vcert.ssl);

    if (peerCerts) {
        Ssl::BIO_Pointer bio(BIO_new(BIO_s_mem()));
        for (int i = 0; i < sk_X509_num(peerCerts); ++i) {
            X509 *cert = sk_X509_value(peerCerts, i);
            PEM_write_bio_X509(bio.get(), cert);
            body = body + "\n" + param_cert + xitoa(i) + "=";
            char *ptr;
            long len = BIO_get_mem_data(bio.get(), &ptr);
            body.append(ptr, (ptr[len-1] == '\n' ? len - 1 : len));
            if (!BIO_reset(bio.get())) {
                // print an error?
            }
        }
    }

    if (vcert.errors) {
        int i = 0;
        for (const Ssl::CertErrors *err = vcert.errors; err; err = err->next, ++i) {
            body +="\n";
            body = body + param_error_name + xitoa(i) + "=" + GetErrorName(err->element.code) + "\n";
            int errorCertPos = -1;
            if (err->element.cert.get())
                errorCertPos = sk_X509_find(peerCerts, err->element.cert.get());
            if (errorCertPos < 0) {
                // assert this error ?
                debugs(83, 4, "WARNING: wrong cert in cert validator request");
            }
            body += param_error_cert + xitoa(i) + "=";
            body += param_cert + xitoa((errorCertPos >= 0 ? errorCertPos : 0));
        }
    }
}

static int
get_error_id(const char *label, size_t len)
{
    const char *e = label + len -1;
    while (e != label && xisdigit(*e)) --e;
    if (e != label) ++e;
    return strtol(e, 0 , 10);
}

bool
Ssl::CertValidationMsg::parseResponse(CertValidationResponse &resp, STACK_OF(X509) *peerCerts, std::string &error)
{
    std::vector<CertItem> certs;

    const char *param = body.c_str();
    while (*param) {
        while (xisspace(*param)) param++;
        if (! *param)
            break;

        size_t param_len = strcspn(param, "=\r\n");
        if (param[param_len] !=  '=') {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: " << param);
            return false;
        }
        const char *value=param+param_len+1;

        if (param_len > param_cert.length() &&
                strncmp(param, param_cert.c_str(), param_cert.length()) == 0) {
            CertItem ci;
            ci.name.assign(param, param_len);
            X509_Pointer x509;
            readCertFromMemory(x509, value);
            ci.setCert(x509.get());
            certs.push_back(ci);

            const char *b = strstr(value, "-----END CERTIFICATE-----");
            if (b == NULL) {
                debugs(83, DBG_IMPORTANT, "WARNING: cert Validator response parse error: Failed  to find certificate boundary " << value);
                return false;
            }
            b += strlen("-----END CERTIFICATE-----");
            param = b + 1;
            continue;
        }

        size_t value_len = strcspn(value, "\r\n");
        std::string v(value, value_len);

        debugs(83, 5, "Returned value: " << std::string(param, param_len).c_str() << ": " <<
               v.c_str());

        int errorId = get_error_id(param, param_len);
        Ssl::CertValidationResponse::RecvdError &currentItem = resp.getError(errorId);

        if (param_len > param_error_name.length() &&
                strncmp(param, param_error_name.c_str(), param_error_name.length()) == 0) {
            currentItem.error_no = Ssl::GetErrorCode(v.c_str());
            if (currentItem.error_no == SSL_ERROR_NONE) {
                debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: Unknown SSL Error: " << v);
                return false;
            }
        } else if (param_len > param_error_reason.length() &&
                   strncmp(param, param_error_reason.c_str(), param_error_reason.length()) == 0) {
            currentItem.error_reason = v;
        } else if (param_len > param_error_cert.length() &&
                   strncmp(param, param_error_cert.c_str(), param_error_cert.length()) == 0) {

            if (X509 *cert = getCertByName(certs, v)) {
                debugs(83, 6, "The certificate with id \"" << v << "\" found.");
                currentItem.setCert(cert);
            } else {
                //In this case we assume that the certID is one of the certificates sent
                // to cert validator. The certificates sent to cert validator have names in
                // form "cert_xx" where the "xx" is an integer represents the position of
                // the certificate inside peer certificates list.
                const int certId = get_error_id(v.c_str(), v.length());
                debugs(83, 6, "Cert index in peer certificates list:" << certId);
                //if certId is not correct sk_X509_value returns NULL
                currentItem.setCert(sk_X509_value(peerCerts, certId));
            }
        } else {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator response parse error: Unknown parameter name " << std::string(param, param_len).c_str());
            return false;
        }

        param = value + value_len;
    }

    /*Run through parsed errors to check for errors*/
    typedef Ssl::CertValidationResponse::RecvdErrors::const_iterator SVCRECI;
    for (SVCRECI i = resp.errors.begin(); i != resp.errors.end(); ++i) {
        if (i->error_no == SSL_ERROR_NONE) {
            debugs(83, DBG_IMPORTANT, "WARNING: cert validator incomplete response: Missing error name from error_id: " << i->id);
            return false;
        }
    }

    return true;
}

X509 *
Ssl::CertValidationMsg::getCertByName(std::vector<CertItem> const &certs, std::string const & name)
{
    typedef std::vector<CertItem>::const_iterator SVCI;
    for (SVCI ci = certs.begin(); ci != certs.end(); ++ci) {
        if (ci->name.compare(name) == 0)
            return ci->cert.get();
    }
    return NULL;
}

Ssl::CertValidationResponse::RecvdError &
Ssl::CertValidationResponse::getError(int errorId)
{
    typedef Ssl::CertValidationResponse::RecvdErrors::iterator SVCREI;
    for (SVCREI i = errors.begin(); i != errors.end(); ++i) {
        if (i->id == errorId)
            return *i;
    }
    Ssl::CertValidationResponse::RecvdError errItem;
    errItem.id = errorId;
    errors.push_back(errItem);
    return errors.back();
}

Ssl::CertValidationResponse::RecvdError::RecvdError(const RecvdError &old)
{
    id = old.id;
    error_no = old.error_no;
    error_reason = old.error_reason;
    setCert(old.cert.get());
}

Ssl::CertValidationResponse::RecvdError & Ssl::CertValidationResponse::RecvdError::operator = (const RecvdError &old)
{
    id = old.id;
    error_no = old.error_no;
    error_reason = old.error_reason;
    setCert(old.cert.get());
    return *this;
}

void
Ssl::CertValidationResponse::RecvdError::setCert(X509 *aCert)
{
    cert.resetAndLock(aCert);
}

Ssl::CertValidationMsg::CertItem::CertItem(const CertItem &old)
{
    name = old.name;
    setCert(old.cert.get());
}

Ssl::CertValidationMsg::CertItem & Ssl::CertValidationMsg::CertItem::operator = (const CertItem &old)
{
    name = old.name;
    setCert(old.cert.get());
    return *this;
}

void
Ssl::CertValidationMsg::CertItem::setCert(X509 *aCert)
{
    cert.resetAndLock(aCert);
}

const std::string Ssl::CertValidationMsg::code_cert_validate("cert_validate");
const std::string Ssl::CertValidationMsg::param_domain("domain");
const std::string Ssl::CertValidationMsg::param_cert("cert_");
const std::string Ssl::CertValidationMsg::param_error_name("error_name_");
const std::string Ssl::CertValidationMsg::param_error_reason("error_reason_");
const std::string Ssl::CertValidationMsg::param_error_cert("error_cert_");
const std::string Ssl::CertValidationMsg::param_proto_version("proto_version");
const std::string Ssl::CertValidationMsg::param_cipher("cipher");

