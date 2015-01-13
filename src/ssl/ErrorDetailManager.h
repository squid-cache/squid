/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SSL_ERRORDETAILMANAGER_H
#define _SQUID_SSL_ERRORDETAILMANAGER_H

#include "base/RefCount.h"
#include "HttpRequest.h"
#include "SquidString.h"
#include "ssl/support.h"

#include <map>
#include <string>

class HttpRequest;

namespace Ssl
{

class ErrorDetailEntry
{
public:
    Ssl::ssl_error_t error_no; ///< The SSL error code
    String name; ///< a name for the error
    String detail; ///< for error page %D macro expansion; may contain macros
    String descr;  ///< short error description (for use in debug messages or error pages)
};

/**
 * Used to hold an error-details.txt template in ram. An error-details,.txt is represented
 * by a list of error detail entries (ErrorDetailEntry objects).
 */
class ErrorDetailsList : public RefCountable
{
public:
    typedef RefCount<ErrorDetailsList> Pointer;
    /**
     * Retrieves the error details  for a given error to "entry" object
     * \return true on success, false otherwise
     */
    bool getRecord(Ssl::ssl_error_t value, ErrorDetailEntry &entry);
    const char *getErrorDescr(Ssl::ssl_error_t value); ///< an error description for an error if exist in list.
    const char *getErrorDetail(Ssl::ssl_error_t value); ///< an error details for an error if exist in list.

    String errLanguage; ///< The language of the error-details.txt template, if any
    typedef std::map<Ssl::ssl_error_t, ErrorDetailEntry> ErrorDetails;
    ErrorDetails theList; ///< The list of error details entries
};

/**
 * It is used to load, manage and query multiple ErrorDetailLists
 * objects.
 */
class ErrorDetailsManager
{
public:
    ErrorDetailsManager();

    static ErrorDetailsManager &GetInstance(); ///< Instance class
    static void Shutdown(); ///< reset the ErrorDetailsManager instance

    /**
     * Retrieve error details for an error. This method examine the Accept-Language
     * of the request to retrieve the error details for  requested language else return
     * the default error details.
     * \param vale the error code
     * \param request the current HTTP request.
     * \param entry where to store error details
     * \return true on success, false otherwise
     */
    bool getErrorDetail(Ssl::ssl_error_t value, const HttpRequest::Pointer &request, ErrorDetailEntry &entry);
    const char *getDefaultErrorDescr(Ssl::ssl_error_t value); ///< the default error description for a given error
    const char *getDefaultErrorDetail(Ssl::ssl_error_t value); ///< the default error details for a given error

private:
    /// Return cached error details list for a given language if exist
    ErrorDetailsList::Pointer getCachedDetails(const char *lang);
    /// cache the given error details list.
    void cacheDetails(ErrorDetailsList::Pointer &errorDetails);

    typedef std::map<std::string, ErrorDetailsList::Pointer> Cache;
    Cache cache; ///< the error details list cache
    ErrorDetailsList::Pointer theDefaultErrorDetails; ///< the default error details list

    /// An instance of ErrorDetailsManager to be used by squid (ssl/ErrorDetails.*)
    static ErrorDetailsManager *TheDetailsManager;
};

void errorDetailInitialize();
void errorDetailClean();
} //namespace Ssl
#endif

