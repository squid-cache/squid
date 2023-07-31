/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/Raw.h"
#include "ErrorDetail.h"
#include "ErrorDetailManager.h"
#include "errorpage.h"
#include "http/ContentLengthInterpreter.h"
#include "mime_header.h"

void Ssl::errorDetailInitialize()
{
    Ssl::ErrorDetailsManager::GetInstance();
}

void Ssl::errorDetailClean()
{
    Ssl::ErrorDetailsManager::Shutdown();
}

namespace Ssl
{

/// manages error detail templates
class ErrorDetailFile : public TemplateFile
{
public:
    explicit ErrorDetailFile(ErrorDetailsList::Pointer const details): TemplateFile("error-details.txt", ERR_NONE) {
        theDetails = details;
    }

private:
    ErrorDetailsList::Pointer  theDetails;
    bool parse() override;
};
}// namespace Ssl

/******************/
bool
Ssl::ErrorDetailsList::getRecord(Security::ErrorCode value, ErrorDetailEntry &entry)
{
    const ErrorDetails::const_iterator it = theList.find(value);
    if (it != theList.end()) {
        entry.error_no =  it->second.error_no;
        entry.name =  it->second.name;
        entry.detail =  it->second.detail;
        entry.descr =  it->second.descr;
        return true;
    }
    return false;
}

const char *
Ssl::ErrorDetailsList::getErrorDescr(Security::ErrorCode value)
{
    const ErrorDetails::const_iterator it = theList.find(value);
    if (it != theList.end()) {
        return it->second.descr.termedBuf();
    }

    return nullptr;
}

const char *
Ssl::ErrorDetailsList::getErrorDetail(Security::ErrorCode value)
{
    const ErrorDetails::const_iterator it = theList.find(value);
    if (it != theList.end()) {
        return it->second.detail.termedBuf();
    }

    return nullptr;
}

Ssl::ErrorDetailsManager *Ssl::ErrorDetailsManager::TheDetailsManager = nullptr;

Ssl::ErrorDetailsManager &Ssl::ErrorDetailsManager::GetInstance()
{
    if (!TheDetailsManager)
        TheDetailsManager = new Ssl::ErrorDetailsManager;

    assert(TheDetailsManager);
    return *TheDetailsManager;
}

void Ssl::ErrorDetailsManager::Shutdown()
{
    delete TheDetailsManager;
    TheDetailsManager = nullptr;
}

Ssl::ErrorDetailsManager::ErrorDetailsManager()
{
    theDefaultErrorDetails = new ErrorDetailsList();
    ErrorDetailFile detailTmpl(theDefaultErrorDetails);
    detailTmpl.loadDefault();
}

Ssl::ErrorDetailsList::Pointer Ssl::ErrorDetailsManager::getCachedDetails(const char *lang)
{
    Cache::iterator it;
    it = cache.find(lang);
    if (it != cache.end()) {
        debugs(83, 8, "Found template details in cache for language: " << lang);
        return it->second;
    }

    return nullptr;
}

void Ssl::ErrorDetailsManager::cacheDetails(ErrorDetailsList::Pointer &errorDetails)
{
    const char *lang = errorDetails->errLanguage.termedBuf();
    assert(lang);
    if (cache.find(lang) == cache.end())
        cache[lang] = errorDetails;
}

bool
Ssl::ErrorDetailsManager::getErrorDetail(Security::ErrorCode value, const HttpRequest::Pointer &request, ErrorDetailEntry &entry)
{
#if USE_ERR_LOCALES
    String hdr;
    if (request != nullptr && request->header.getList(Http::HdrType::ACCEPT_LANGUAGE, &hdr)) {
        ErrorDetailsList::Pointer errDetails = nullptr;
        //Try to retrieve from cache
        size_t pos = 0;
        char lang[256];
        // Get the first ellement of the Accept-Language header
        strHdrAcptLangGetItem(hdr, lang, 256, pos);
        errDetails = getCachedDetails(lang); // search in cache

        if (!errDetails) { // Else try to load from disk
            debugs(83, 8, "Creating new ErrDetailList to read from disk");
            errDetails = new ErrorDetailsList();
            ErrorDetailFile detailTmpl(errDetails);
            if (detailTmpl.loadFor(request.getRaw())) {
                if (detailTmpl.language()) {
                    debugs(83, 8, "Found details on disk for language " << detailTmpl.language());
                    errDetails->errLanguage = detailTmpl.language();
                    cacheDetails(errDetails);
                }
            }
        }

        if (errDetails != nullptr && errDetails->getRecord(value, entry))
            return true;
    }
#else
    (void)request;
#endif

    // else try the default
    if (theDefaultErrorDetails->getRecord(value, entry)) {
        debugs(83, 8, "Found default details record for error: " << GetErrorName(value));
        return true;
    }

    return false;
}

const char *
Ssl::ErrorDetailsManager::getDefaultErrorDescr(Security::ErrorCode value)
{
    return theDefaultErrorDetails->getErrorDescr(value);
}

const char *
Ssl::ErrorDetailsManager::getDefaultErrorDetail(Security::ErrorCode value)
{
    return theDefaultErrorDetails->getErrorDetail(value);
}

// Use HttpHeaders parser to parse error-details.txt files
class DetailEntryParser: public HttpHeader
{
public:
    DetailEntryParser():HttpHeader(hoErrorDetail) {}
};

//The end of an error detrail entry is a double "\n". The headersEnd
// functions can detect it
inline size_t detailEntryEnd(const char *s, size_t len) {return headersEnd(s, len);}

bool
Ssl::ErrorDetailFile::parse()
{
    if (!theDetails)
        return false;

    auto buf = template_;
    buf.append("\n\n"); // ensure detailEntryEnd() finds the last entry

    while (const auto size = detailEntryEnd(buf.rawContent(), buf.length())) {
        auto *s = buf.c_str();
        const auto e = s + size;

        //ignore spaces, new lines and comment lines (starting with #) at the beginning
        for (; (*s == '\n' || *s == ' '  || *s == '\t' || *s == '#')  && s < e; ++s) {
            if (*s == '#')
                while (s<e &&  *s != '\n')
                    ++s; // skip until the end of line
        }

        if ( s != e) {
            DetailEntryParser parser;
            Http::ContentLengthInterpreter interpreter;
            // no applyStatusCodeRules() -- error templates lack HTTP status code
            if (!parser.parse(s, e - s, interpreter)) {
                debugs(83, DBG_IMPORTANT, "WARNING: parse error on:" << s);
                return false;
            }

            const String errorName = parser.getByName("name");
            if (!errorName.size()) {
                debugs(83, DBG_IMPORTANT, "WARNING: invalid or no error detail name on:" << s);
                return false;
            }

            Security::ErrorCode ssl_error = Ssl::GetErrorCode(errorName.termedBuf());
            if (ssl_error != SSL_ERROR_NONE) {

                if (theDetails->getErrorDetail(ssl_error)) {
                    debugs(83, DBG_IMPORTANT, "WARNING: duplicate entry: " << errorName);
                    return false;
                }

                ErrorDetailEntry &entry = theDetails->theList[ssl_error];
                entry.error_no = ssl_error;
                entry.name = errorName;
                String tmp = parser.getByName("detail");
                const int detailsParseOk = httpHeaderParseQuotedString(tmp.termedBuf(), tmp.size(), &entry.detail);
                tmp = parser.getByName("descr");
                const int descrParseOk = httpHeaderParseQuotedString(tmp.termedBuf(), tmp.size(), &entry.descr);
                // TODO: Validate "descr" and "detail" field values.

                if (!detailsParseOk || !descrParseOk) {
                    debugs(83, DBG_IMPORTANT, "WARNING: missing important field for detail error: " <<  errorName);
                    return false;
                }

            } else if (!Ssl::ErrorIsOptional(errorName.termedBuf())) {
                debugs(83, DBG_IMPORTANT, "WARNING: invalid error detail name: " << errorName);
                return false;
            }

        }// else {only spaces and black lines; just ignore}

        buf.consume(size);
    }
    debugs(83, 9, Raw("unparsed data", buf.rawContent(), buf.length()));
    return true;
}

