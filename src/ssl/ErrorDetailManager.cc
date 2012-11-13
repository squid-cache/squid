#include "squid.h"
#include "ErrorDetail.h"
#include "errorpage.h"
#include "ErrorDetailManager.h"
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
        buf.init();
        theDetails = details;
    }

private:
    MemBuf buf;
    ErrorDetailsList::Pointer  theDetails;
    virtual bool parse(const char *buf, int len, bool eof);
};
}// namespace Ssl

/******************/
bool
Ssl::ErrorDetailsList::getRecord(Ssl::ssl_error_t value, ErrorDetailEntry &entry)
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
Ssl::ErrorDetailsList::getErrorDescr(Ssl::ssl_error_t value)
{
    const ErrorDetails::const_iterator it = theList.find(value);
    if (it != theList.end()) {
        return it->second.descr.termedBuf();
    }

    return NULL;
}

const char *
Ssl::ErrorDetailsList::getErrorDetail(Ssl::ssl_error_t value)
{
    const ErrorDetails::const_iterator it = theList.find(value);
    if (it != theList.end()) {
        return it->second.detail.termedBuf();
    }

    return NULL;
}

Ssl::ErrorDetailsManager *Ssl::ErrorDetailsManager::TheDetailsManager = NULL;

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
    TheDetailsManager = NULL;
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
        debugs(83, 8, HERE << "Found template details in cache for language: " << lang);
        return it->second;
    }

    return NULL;
}

void Ssl::ErrorDetailsManager::cacheDetails(ErrorDetailsList::Pointer &errorDetails)
{
    const char *lang = errorDetails->errLanguage.termedBuf();
    assert(lang);
    if (cache.find(lang) == cache.end())
        cache[lang] = errorDetails;
}

bool
Ssl::ErrorDetailsManager::getErrorDetail(Ssl::ssl_error_t value, HttpRequest *request, ErrorDetailEntry &entry)
{
#if USE_ERR_LOCALES
    String hdr;
    if (request && request->header.getList(HDR_ACCEPT_LANGUAGE, &hdr)) {
        ErrorDetailsList::Pointer errDetails = NULL;
        //Try to retrieve from cache
        size_t pos = 0;
        char lang[256];
        // Get the first ellement of the Accept-Language header
        strHdrAcptLangGetItem(hdr, lang, 256, pos);
        errDetails = getCachedDetails(lang); // search in cache

        if (!errDetails) { // Else try to load from disk
            debugs(83, 8, HERE << "Creating new ErrDetailList to read from disk");
            errDetails = new ErrorDetailsList();
            ErrorDetailFile detailTmpl(errDetails);
            if (detailTmpl.loadFor(request)) {
                if (detailTmpl.language()) {
                    debugs(83, 8, HERE << "Found details on disk for language " << detailTmpl.language());
                    errDetails->errLanguage = detailTmpl.language();
                    cacheDetails(errDetails);
                }
            }
        }

        if (errDetails != NULL && errDetails->getRecord(value, entry))
            return true;
    }
#endif

    // else try the default
    if (theDefaultErrorDetails->getRecord(value, entry)) {
        debugs(83, 8, HERE << "Found default details record for error: " << GetErrorName(value));
        return true;
    }

    return false;
}

const char *
Ssl::ErrorDetailsManager::getDefaultErrorDescr(Ssl::ssl_error_t value)
{
    return theDefaultErrorDetails->getErrorDescr(value);
}

const char *
Ssl::ErrorDetailsManager::getDefaultErrorDetail(Ssl::ssl_error_t value)
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
Ssl::ErrorDetailFile::parse(const char *buffer, int len, bool eof)
{
    if (!theDetails)
        return false;

    if (len) {
        buf.append(buffer, len);
    }

    if (eof)
        buf.append("\n\n", 1);

    while (size_t size = detailEntryEnd(buf.content(), buf.contentSize())) {
        const char *e = buf.content() + size;

        //ignore spaces, new lines and comment lines (starting with #) at the beggining
        const char *s;
        for (s = buf.content(); (*s == '\n' || *s == ' '  || *s == '\t' || *s == '#')  && s < e; ++s) {
            if (*s == '#')
                while (s<e &&  *s != '\n')
                    ++s; // skip untill the end of line
        }

        if ( s != e) {
            DetailEntryParser parser;
            if (!parser.parse(s, e)) {
                debugs(83, DBG_IMPORTANT, HERE <<
                       "WARNING! parse error on:" << s);
                return false;
            }

            const String errorName = parser.getByName("name");
            if (!errorName.size()) {
                debugs(83, DBG_IMPORTANT, HERE <<
                       "WARNING! invalid or no error detail name on:" << s);
                return false;
            }

            Ssl::ssl_error_t ssl_error = Ssl::GetErrorCode(errorName.termedBuf());
            if (ssl_error == SSL_ERROR_NONE) {
                debugs(83, DBG_IMPORTANT, HERE <<
                       "WARNING! invalid error detail name: " << errorName);
                return false;
            }

            if (theDetails->getErrorDetail(ssl_error)) {
                debugs(83, DBG_IMPORTANT, HERE <<
                       "WARNING! duplicate entry: " << errorName);
                return false;
            }

            ErrorDetailEntry &entry = theDetails->theList[ssl_error];
            entry.error_no = ssl_error;
            entry.name = errorName;
            String tmp = parser.getByName("detail");
            httpHeaderParseQuotedString(tmp.termedBuf(), tmp.size(), &entry.detail);
            tmp = parser.getByName("descr");
            httpHeaderParseQuotedString(tmp.termedBuf(), tmp.size(), &entry.descr);
            bool parseOK = entry.descr.defined() && entry.detail.defined();

            if (!parseOK) {
                debugs(83, DBG_IMPORTANT, HERE <<
                       "WARNING! missing imporant field for detail error: " <<  errorName);
                return false;
            }
        }// else {only spaces and black lines; just ignore}

        buf.consume(size);
    }
    debugs(83, 9, HERE << " Remain size: " << buf.contentSize() << " Content: " << buf.content());
    return true;
}
