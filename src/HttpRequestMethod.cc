/*
 * DEBUG: section 73    HTTP Request
 */

#include "squid.h"
#include "HttpRequestMethod.h"
#include "wordlist.h"

static Http::MethodType &
operator++ (Http::MethodType &aMethod)
{
    int tmp = (int)aMethod;
    aMethod = (Http::MethodType)(++tmp);
    return aMethod;
}

/**
 * Construct a HttpRequestMethod from a NULL terminated string such as "GET"
 * or from a range of chars, * such as "GET" from "GETFOOBARBAZ"
 * (pass in pointer to G and pointer to F.)
 */
HttpRequestMethod::HttpRequestMethod(char const *begin, char const *end) : theMethod (Http::METHOD_NONE)
{
    if (begin == NULL)
        return;

    /*
     * This check for '%' makes sure that we don't
     * match one of the extension method placeholders,
     * which have the form %EXT[0-9][0-9]
     */

    if (*begin == '%')
        return;

    /*
     * if e is NULL, b must be NULL terminated and we
     * make e point to the first whitespace character
     * after b.
     */
    if (NULL == end)
        end = begin + strcspn(begin, w_space);

    if (end == begin) {
        theMethod = Http::METHOD_NONE;
        return;
    }

    for (++theMethod; theMethod < Http::METHOD_ENUM_END; ++theMethod) {
        if (0 == strncasecmp(begin, Http::MethodType_str[theMethod], end-begin)) {
            return;
        }
    }

    // if method not found and method string is not null then it is other method
    theMethod = Http::METHOD_OTHER;
    theImage.limitInit(begin,end-begin);
}

char const*
HttpRequestMethod::image() const
{
    if (Http::METHOD_OTHER != theMethod) {
        return Http::MethodType_str[theMethod];
    } else {
        if (theImage.size()>0) {
            return theImage.termedBuf();
        } else {
            return "METHOD_OTHER";
        }
    }
}

bool
HttpRequestMethod::isHttpSafe() const
{
    // Only a few methods are defined as safe. All others are "unsafe"

    // NOTE:
    // All known RFCs which register methods are listed in comments.
    // if there is one not listed which defines methods, it needs
    // checking and adding. If only to say it is known to define none.

    switch (theMethod) {
        // RFC 2068 - none

        // RFC 2616 section 9.1.1
    case Http::METHOD_GET:
    case Http::METHOD_HEAD:
    case Http::METHOD_OPTIONS:

        // RFC 3253 section 3.6
    case Http::METHOD_REPORT:

        // RFC 3648 - none
        // RFC 3744 - none
        // RFC 4437 - none
        // RFC 4791 - none

        // RFC 4918 section 9.1
    case Http::METHOD_PROPFIND:

        // RFC 5323 section 2
    case Http::METHOD_SEARCH:

        // RFC 5789 - none
        // RFC 5842 - none

        return true;

    default:
        return false;
    }
}

bool
HttpRequestMethod::isIdempotent() const
{
    // Only a few methods are defined as idempotent.

    // NOTE:
    // All known RFCs which register methods are listed in comments.
    // if there is one not listed which defines methods, it needs
    // checking and adding. If only to say it is known to define none.

    switch (theMethod) {
        // RFC 2068 - TODO check LINK/UNLINK definition

        // RFC 2616 section 9.1.2
    case Http::METHOD_GET:
    case Http::METHOD_HEAD:
    case Http::METHOD_PUT:
    case Http::METHOD_DELETE:
    case Http::METHOD_OPTIONS:
    case Http::METHOD_TRACE:

        // RFC 3253 - TODO check
        // RFC 3648 - TODO check
        // RFC 3744 - TODO check
        // RFC 4437 - TODO check
        // RFC 4791 - TODO check

        // RFC 4918 section 9
    case Http::METHOD_PROPFIND:
    case Http::METHOD_PROPPATCH:
    case Http::METHOD_MKCOL:
    case Http::METHOD_COPY:
    case Http::METHOD_MOVE:
    case Http::METHOD_UNLOCK:

        // RFC 5323 - TODO check
        // RFC 5789 - TODO check
        // RFC 5842 - TODO check

        return true;

    default:
        return false;
    }
}

bool
HttpRequestMethod::respMaybeCacheable() const
{
    // Only a few methods are defined as cacheable.
    // All other methods from the below RFC are "MUST NOT cache"
    switch (theMethod) {
        // RFC 2616 section 9
    case Http::METHOD_GET:
    case Http::METHOD_HEAD:
        return true;
#if WHEN_POST_CACHE_SUPPORTED
    case Http::METHOD_POST: // Special case.
        // RFC 2616 specifies POST as possibly cacheable
        // However, Squid does not implement the required checks yet
        return true;
#endif

        // RFC 4918 section 9
#if WHEN_PROPFIND_CACHE_SUPPORTED
    case Http::METHOD_PROPFIND: // Special case.
        // RFC 4918 specifies PROPFIND as possibly cacheable
        // However, Squid does not implement the required checks yet
        return true;
#endif

        // RFC 5323 section 2 - defines no cacheable methods

        // RFC 3253
#if WHEN_CC_NOCACHE_DOES_REVALIDATES_IS_CONFIRMED
    case Http::METHOD_CHECKOUT:
    case Http::METHOD_CHECKIN:
    case Http::METHOD_UNCHECKOUT:
    case Http::METHOD_MKWORKSPACE:
    case Http::METHOD_VERSION_CONTROL:
    case Http::METHOD_UPDATE:
    case Http::METHOD_LABEL:
    case Http::METHOD_MERGE:
    case Http::METHOD_BASELINE_CONTROL:
    case Http::METHOD_MKACTIVITY:
        // RFC 3253 defines these methods using "MUST include Cache-Control: no-cache".
        //
        // XXX: follow RFC 2616 definition of "no-cache" meaning "MAY cache, always revalidate"
        // XXX: or treat as unregistered/undefined methods ??
        // However, Squid may not implement the required revalidation checks yet
        return ??;
#endif

        // Special Squid method tokens are not cacheable.
        // RFC 2616 defines all unregistered or unspecified methods as non-cacheable
        // until such time as an RFC defines them cacheable.
    default:
        return false;
    }
}

bool
HttpRequestMethod::shouldInvalidate() const
{
    switch (theMethod) {
        /* RFC 2616 section 13.10 - "MUST invalidate" */
    case Http::METHOD_POST:
    case Http::METHOD_PUT:
    case Http::METHOD_DELETE:
        return true;

        /* Squid extension to force invalidation */
    case Http::METHOD_PURGE:
        return true;

        /*
         * RFC 2616 sayeth, in section 13.10, final paragraph:
         * A cache that passes through requests for methods it does not
         * understand SHOULD invalidate any entities referred to by the
         * Request-URI.
         */
    case Http::METHOD_OTHER:
        return true;

    default:
        // Methods which are known but not required to invalidate.
        return false;
    }
}

bool
HttpRequestMethod::purgesOthers() const
{
    if (shouldInvalidate())
        return true;

    switch (theMethod) {
        /* common sense suggests purging is not required? */
    case Http::METHOD_GET:     // XXX: but we do purge HEAD on successful GET
    case Http::METHOD_HEAD:
    case Http::METHOD_NONE:
    case Http::METHOD_CONNECT:
    case Http::METHOD_TRACE:
    case Http::METHOD_OPTIONS:
    case Http::METHOD_PROPFIND:
    case Http::METHOD_COPY:
    case Http::METHOD_LOCK:
    case Http::METHOD_UNLOCK:
    case Http::METHOD_SEARCH:
        return false;

    default:
        return true;
    }
}
