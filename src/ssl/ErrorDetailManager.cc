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
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"

void Ssl::errorDetailInitialize()
{
    Ssl::ErrorDetailsManager::GetInstance();
}

void Ssl::errorDetailClean()
{
    Ssl::ErrorDetailsManager::Shutdown();
}

/// ErrorDetailEntry constructor helper that extracts a quoted HTTP field value
static SBuf
SlowlyParseQuotedField(const char * const description, const HttpHeader &parser, const char * const fieldName)
{
    String fieldValue;
    if (!parser.hasNamed(fieldName, strlen(fieldName), &fieldValue))
        throw TextException(ToSBuf("Missing ", description), Here());
    return Http::SlowlyParseQuotedString(description, fieldValue.termedBuf(), fieldValue.size());
}

Ssl::ErrorDetailEntry::ErrorDetailEntry(const SBuf &aName, const HttpHeader &fields):
    name(aName),
    detail(SlowlyParseQuotedField("error 'detail' field", fields, "detail")),
    descr(SlowlyParseQuotedField("error 'descr' field", fields, "descr"))
{
    // TODO: Warn about and report extra/unrecognized error detail fields.
    // TODO: Validate formatting %codes inside parsed quoted field values.
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
const Ssl::ErrorDetailEntry *
Ssl::ErrorDetailsList::findRecord(Security::ErrorCode value) const
{
    const ErrorDetails::const_iterator it = theList.find(value);
    return it != theList.end() ? &it->second : nullptr;
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

Ssl::ErrorDetailsList::Pointer
Ssl::ErrorDetailsManager::getCachedDetails(const char * const lang) const
{
    Cache::iterator it;
    it = cache.find(SBuf(lang));
    if (it != cache.end()) {
        debugs(83, 8, "Found template details in cache for language: " << lang);
        return it->second;
    }

    return nullptr;
}

void
Ssl::ErrorDetailsManager::cacheDetails(const ErrorDetailsList::Pointer &errorDetails) const
{
    const auto &lang = errorDetails->errLanguage;
    if (cache.find(lang) == cache.end())
        cache[lang] = errorDetails;
}

const Ssl::ErrorDetailEntry *
Ssl::ErrorDetailsManager::findDetail(const Security::ErrorCode value, const HttpRequest::Pointer &request) const
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

        assert(errDetails);
        if (const auto entry = errDetails->findRecord(value))
            return entry;
    }
#else
    (void)request;
#endif

    return findDefaultDetail(value);
}

const Ssl::ErrorDetailEntry *
Ssl::ErrorDetailsManager::findDefaultDetail(const Security::ErrorCode value) const
{
    return theDefaultErrorDetails->findRecord(value);
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

                if (theDetails->findRecord(ssl_error)) {
                    debugs(83, DBG_IMPORTANT, "WARNING: duplicate entry: " << errorName);
                    return false;
                }

                try {
                    theDetails->theList.try_emplace(ssl_error, StringToSBuf(errorName), parser);
                }
                catch (...) {
                    // TODO: Reject the whole file on this and surrounding problems instead of
                    // keeping/using just the previously parsed entries while telling the admin
                    // that we "failed to find or read error text file error-details.txt".
                    debugs(83, DBG_IMPORTANT, "ERROR: Ignoring bad " << errorName << " detail entry: " << CurrentException);
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

