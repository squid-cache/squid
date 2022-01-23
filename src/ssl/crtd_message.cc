/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ssl/crtd_message.h"
#include "ssl/gadgets.h"

#include <cstdlib>
#include <cstring>
#include <stdexcept>

Ssl::CrtdMessage::CrtdMessage(MessageKind kind)
    :   body_size(0), state(kind == REPLY ? BEFORE_LENGTH: BEFORE_CODE)
{}

Ssl::CrtdMessage::ParseResult Ssl::CrtdMessage::parse(const char * buffer, size_t len)
{
    char const *current_pos = buffer;
    while (current_pos != buffer + len && state != END) {
        switch (state) {
        case BEFORE_CODE: {
            if (xisspace(*current_pos)) {
                ++current_pos;
                break;
            }
            if (xisalpha(*current_pos)) {
                state = CODE;
                break;
            }
            clear();
            return ERROR;
        }
        case CODE: {
            if (xisalnum(*current_pos) || *current_pos == '_') {
                current_block += *current_pos;
                ++current_pos;
                break;
            }
            if (xisspace(*current_pos)) {
                code = current_block;
                current_block.clear();
                state = BEFORE_LENGTH;
                break;
            }
            clear();
            return ERROR;
        }
        case BEFORE_LENGTH: {
            if (xisspace(*current_pos)) {
                ++current_pos;
                break;
            }
            if (xisdigit(*current_pos)) {
                state = LENGTH;
                break;
            }
            clear();
            return ERROR;
        }
        case LENGTH: {
            if (xisdigit(*current_pos)) {
                current_block += *current_pos;
                ++current_pos;
                break;
            }
            if (xisspace(*current_pos)) {
                body_size = atoi(current_block.c_str());
                current_block.clear();
                state = BEFORE_BODY;
                break;
            }
            clear();
            return ERROR;
        }
        case BEFORE_BODY: {
            if (body_size == 0) {
                state = END;
                break;
            }
            if (xisspace(*current_pos)) {
                ++current_pos;
                break;
            } else {
                state = BODY;
                break;
            }
        }
        case BODY: {
            size_t body_len = (static_cast<size_t>(buffer + len - current_pos) >= body_size - current_block.length())
                              ? body_size - current_block.length()
                              : static_cast<size_t>(buffer + len - current_pos);
            current_block += std::string(current_pos, body_len);
            current_pos += body_len;
            if (current_block.length() == body_size) {
                body = current_block;
                state = END;
            }
            if (current_block.length() > body_size) {
                clear();
                return ERROR;
            }
            break;
        }
        case END: {
            return OK;
        }
        }
    }
    if (state != END) return INCOMPLETE;
    return OK;
}

std::string const & Ssl::CrtdMessage::getBody() const { return body; }

std::string const & Ssl::CrtdMessage::getCode() const { return code; }

void Ssl::CrtdMessage::setBody(std::string const & aBody) { body = aBody; }

void Ssl::CrtdMessage::setCode(std::string const & aCode) { code = aCode; }

std::string Ssl::CrtdMessage::compose() const
{
    if (code.empty()) return std::string();
    char buffer[10];
    snprintf(buffer, sizeof(buffer), "%zd", body.length());
    return code + ' ' + buffer + ' ' + body;
}

void Ssl::CrtdMessage::clear()
{
    body_size = 0;
    state = BEFORE_CODE;
    body.clear();
    code.clear();
    current_block.clear();
}

void Ssl::CrtdMessage::parseBody(CrtdMessage::BodyParams & map, std::string & other_part) const
{
    other_part.clear();
    // Copy string for using it as temp buffer.
    std::string temp_body(body.c_str(), body.length());
    char * buffer = const_cast<char *>(temp_body.c_str());
    char * token = strtok(buffer, "\r\n");
    while (token != NULL) {
        std::string current_string(token);
        size_t equal_pos = current_string.find('=');
        if (equal_pos == std::string::npos) {
            size_t offset_body_part = token - temp_body.c_str();
            other_part = std::string(body.c_str() + offset_body_part, body.length() - offset_body_part);
            break;
        } else {
            std::string param(current_string.c_str(), current_string.c_str() + equal_pos);
            std::string value(current_string.c_str() + equal_pos + 1);
            map.insert(std::make_pair(param, value));
        }
        token = strtok(NULL, "\r\n");
    }
}

void Ssl::CrtdMessage::composeBody(CrtdMessage::BodyParams const & map, std::string const & other_part)
{
    body.clear();
    for (BodyParams::const_iterator i = map.begin(); i != map.end(); ++i) {
        if (i != map.begin())
            body += "\n";
        body += i->first + "=" + i->second;
    }
    if (!other_part.empty())
        body += '\n' + other_part;
}

bool Ssl::CrtdMessage::parseRequest(Ssl::CertificateProperties &certProperties, std::string &error)
{
    Ssl::CrtdMessage::BodyParams map;
    std::string certs_part;
    parseBody(map, certs_part);
    Ssl::CrtdMessage::BodyParams::iterator i = map.find(Ssl::CrtdMessage::param_host);
    if (i == map.end()) {
        error = "Cannot find \"host\" parameter in request message";
        return false;
    }
    certProperties.commonName = i->second;

    i = map.find(Ssl::CrtdMessage::param_SetValidAfter);
    if (i != map.end() && strcasecmp(i->second.c_str(), "on") == 0)
        certProperties.setValidAfter = true;

    i = map.find(Ssl::CrtdMessage::param_SetValidBefore);
    if (i != map.end() && strcasecmp(i->second.c_str(), "on") == 0)
        certProperties.setValidBefore = true;

    i = map.find(Ssl::CrtdMessage::param_SetCommonName);
    if (i != map.end()) {
        // use this as Common Name  instead of the hostname
        // defined with host or Common Name from mimic cert
        certProperties.commonName = i->second;
        certProperties.setCommonName = true;
    }

    i = map.find(Ssl::CrtdMessage::param_Sign);
    if (i != map.end()) {
        if ((certProperties.signAlgorithm = Ssl::certSignAlgorithmId(i->second.c_str())) == Ssl::algSignEnd) {
            error = "Wrong signing algoritm: ";
            error += i->second;
            return false;
        }
    } else
        certProperties.signAlgorithm = Ssl::algSignTrusted;

    i = map.find(Ssl::CrtdMessage::param_SignHash);
    const char *signHashName = i != map.end() ? i->second.c_str() : SQUID_SSL_SIGN_HASH_IF_NONE;
    if (!(certProperties.signHash = EVP_get_digestbyname(signHashName))) {
        error = "Wrong signing hash: ";
        error += signHashName;
        return false;
    }

    if (!Ssl::readCertAndPrivateKeyFromMemory(certProperties.signWithX509, certProperties.signWithPkey, certs_part.c_str())) {
        error = "Broken signing certificate!";
        return false;
    }

    static const std::string CERT_BEGIN_STR("-----BEGIN CERTIFICATE");
    size_t pos;
    if ((pos = certs_part.find(CERT_BEGIN_STR)) != std::string::npos) {
        pos += CERT_BEGIN_STR.length();
        if ((pos= certs_part.find(CERT_BEGIN_STR, pos)) != std::string::npos)
            Ssl::readCertFromMemory(certProperties.mimicCert, certs_part.c_str() + pos);
    }
    return true;
}

void Ssl::CrtdMessage::composeRequest(Ssl::CertificateProperties const &certProperties)
{
    body.clear();
    body = Ssl::CrtdMessage::param_host + "=" + certProperties.commonName;
    if (certProperties.setCommonName)
        body +=  "\n" + Ssl::CrtdMessage::param_SetCommonName + "=" + certProperties.commonName;
    if (certProperties.setValidAfter)
        body +=  "\n" + Ssl::CrtdMessage::param_SetValidAfter + "=on";
    if (certProperties.setValidBefore)
        body +=  "\n" + Ssl::CrtdMessage::param_SetValidBefore + "=on";
    if (certProperties.signAlgorithm != Ssl::algSignEnd)
        body +=  "\n" +  Ssl::CrtdMessage::param_Sign + "=" +  certSignAlgorithm(certProperties.signAlgorithm);
    if (certProperties.signHash)
        body +=  "\n" + Ssl::CrtdMessage::param_SignHash + "=" + EVP_MD_name(certProperties.signHash);

    std::string certsPart;
    if (!Ssl::writeCertAndPrivateKeyToMemory(certProperties.signWithX509, certProperties.signWithPkey, certsPart))
        throw std::runtime_error("Ssl::writeCertAndPrivateKeyToMemory()");
    if (certProperties.mimicCert.get()) {
        if (!Ssl::appendCertToMemory(certProperties.mimicCert, certsPart))
            throw std::runtime_error("Ssl::appendCertToMemory()");
    }
    body += "\n" + certsPart;
}

const std::string Ssl::CrtdMessage::code_new_certificate("new_certificate");
const std::string Ssl::CrtdMessage::param_host("host");
const std::string Ssl::CrtdMessage::param_SetValidAfter(Ssl::CertAdaptAlgorithmStr[algSetValidAfter]);
const std::string Ssl::CrtdMessage::param_SetValidBefore(Ssl::CertAdaptAlgorithmStr[algSetValidBefore]);
const std::string Ssl::CrtdMessage::param_SetCommonName(Ssl::CertAdaptAlgorithmStr[algSetCommonName]);
const std::string Ssl::CrtdMessage::param_Sign("Sign");
const std::string Ssl::CrtdMessage::param_SignHash("SignHash");

