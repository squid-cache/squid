/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREQUESTMETHOD_H
#define SQUID_HTTPREQUESTMETHOD_H

#include "http/forward.h"
#include "http/MethodType.h"
#include "sbuf/SBuf.h"

class SquidConfig;

#include <iosfwd>

/**
 * This class represents an HTTP Request METHOD
 * - i.e. PUT, POST, GET etc.
 * It has a runtime extension facility to allow it to
 * efficiently support new methods
 */
class HttpRequestMethod
{
public:
    HttpRequestMethod() : theMethod(Http::METHOD_NONE), theImage() {}
    HttpRequestMethod(Http::MethodType const aMethod) : theMethod(aMethod), theImage() {}
    explicit HttpRequestMethod(const SBuf &);

    void HttpRequestMethodXXX(char const *); // deprecated old c-string to SBuf converter.

    HttpRequestMethod & operator = (Http::MethodType const aMethod) {
        theMethod = aMethod;
        theImage.clear();
        return *this;
    }

    /// whether the method is set/known
    explicit operator bool() const { return theMethod != Http::METHOD_NONE; }

    bool operator == (Http::MethodType const & aMethod) const { return theMethod == aMethod; }
    bool operator == (HttpRequestMethod const & aMethod) const {
        return theMethod == aMethod.theMethod &&
               (theMethod != Http::METHOD_OTHER || theImage == aMethod.theImage);
    }

    bool operator != (Http::MethodType const & aMethod) const { return theMethod != aMethod; }
    bool operator != (HttpRequestMethod const & aMethod) const {
        return !operator==(aMethod);
    }

    /** Iterate through all HTTP method IDs. */
    HttpRequestMethod& operator++() {
        // TODO: when this operator is used in more than one place,
        // replace it with HttpRequestMethods::Iterator API
        // XXX: this interface can create Http::METHOD_OTHER without an image
        assert(theMethod < Http::METHOD_ENUM_END);
        theMethod = (Http::MethodType)(1 + (int)theMethod);
        return *this;
    }

    /** Get an ID representation of the method.
     * \retval Http::METHOD_NONE   the method is unset
     * \retval Http::METHOD_OTHER  the method is not recognized and has no unique ID
     * \retval *                   the method is on of the recognized HTTP methods.
     */
    Http::MethodType id() const { return theMethod; }

    /** Get a string representation of the method. */
    const SBuf &image() const;

    /// Whether this method is defined as a "safe" in HTTP/1.1
    /// see RFC 2616 section 9.1.1
    bool isHttpSafe() const;

    /// Whether this method is defined as "idempotent" in HTTP/1.1
    /// see RFC 2616 section 9.1.2
    bool isIdempotent() const;

    /** Whether responses to this method MAY be cached.
     * \retval false  Not cacheable.
     * \retval true   Possibly cacheable. Other details will determine.
     */
    bool respMaybeCacheable() const;

    /** Whether this method SHOULD (or MUST) invalidate existing cached entries.
     * Invalidation is always determined by the response
     *
     * RFC 2616 defines invalidate as either immediate purge
     * or delayed explicit revalidate all stored copies on next use.
     *
     * \retval true   SHOULD invalidate. Response details can raise this to a MUST.
     * \retval false  Other details will determine. Method is not a factor.
     */
    bool shouldInvalidate() const;

    /* Whether this method invalidates existing cached entries.
     * Kept for backward-compatibility. This is the old 2.x-3.2 invalidation behaviour.
     *
     * NOTE:
     *    purgesOthers differs from shouldInvalidate() in that purgesOthers() returns
     *    true on any methods the MAY invalidate (Squid opts to do so).
     *    shouldInvalidate() only returns true on methods which SHOULD invalidate.
     */
    bool purgesOthers() const;

private:
    Http::MethodType theMethod; ///< Method type
    SBuf theImage;     ///< Used for storing the Http::METHOD_OTHER only. A copy of the parsed method text.
};

inline std::ostream &
operator << (std::ostream &os, HttpRequestMethod const &method)
{
    os << method.image();
    return os;
}

#endif /* SQUID_HTTPREQUESTMETHOD_H */

