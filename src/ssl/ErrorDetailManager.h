/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_SSL_ERRORDETAILMANAGER_H
#define SQUID_SRC_SSL_ERRORDETAILMANAGER_H

#include "base/RefCount.h"
#include "HttpRequest.h"
#include "sbuf/SBuf.h"
#include "ssl/support.h"

#include <map>

class HttpRequest;

namespace Ssl
{

class ErrorDetailEntry
{
public:
    /// extracts quoted detail and descr fields from the given header
    ErrorDetailEntry(const SBuf &aName, const HttpHeader &);

    SBuf name; ///< a name for the error
    SBuf detail; ///< for error page %D macro expansion; may contain macros
    SBuf descr; ///< short error description (for use in debug messages or error pages)
};

/**
 * Used to hold an error-details.txt template in ram. An error-details,.txt is represented
 * by a list of error detail entries (ErrorDetailEntry objects).
 */
class ErrorDetailsList : public RefCountable
{
public:
    typedef RefCount<ErrorDetailsList> Pointer;

    /// looks up metadata details for a given error (or nil); returned pointer
    /// is invalidated by any non-constant operation on the list object
    const ErrorDetailEntry *findRecord(Security::ErrorCode) const;

    SBuf errLanguage; ///< The language of the error-details.txt template, if any
    typedef std::map<Security::ErrorCode, ErrorDetailEntry> ErrorDetails;
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
     * \param value the error code
     * \param request the current HTTP request.
     */
    const ErrorDetailEntry *findDetail(Security::ErrorCode value, const HttpRequest::Pointer &request) const;

    /// Default error details for the given TLS error known to Squid (or, if the
    /// error is unknown, nil). Use findDetail() instead when the error is tied
    /// to a specific request.
    const ErrorDetailEntry *findDefaultDetail(Security::ErrorCode) const;

private:
    /// Return cached error details list for a given language if exist
    ErrorDetailsList::Pointer getCachedDetails(const char *lang) const;
    /// cache the given error details list.
    void cacheDetails(const ErrorDetailsList::Pointer &errorDetails) const;

    using Cache = std::map<SBuf, ErrorDetailsList::Pointer>;
    mutable Cache cache; ///< the error details list cache
    ErrorDetailsList::Pointer theDefaultErrorDetails; ///< the default error details list

    /// An instance of ErrorDetailsManager to be used by squid (ssl/ErrorDetails.*)
    static ErrorDetailsManager *TheDetailsManager;
};

void errorDetailInitialize();
void errorDetailClean();
} //namespace Ssl
#endif /* SQUID_SRC_SSL_ERRORDETAILMANAGER_H */

