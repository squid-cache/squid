/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_STATUSCODE_H
#define _SQUID_SRC_HTTP_STATUSCODE_H

namespace Http
{

/**
 * These basic HTTP reply status codes are defined by RFC 2616 unless otherwise stated.
 * The IANA registry for HTTP status codes can be found at:
 * http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 */
typedef enum {
    scNone = 0,
    scContinue = 100,
    scSwitchingProtocols = 101,
    scProcessing = 102,      /**< RFC2518 section 10.1 */
    scEarlyHints = 103,      /**< draft-kazuho-early-hints-status-code */
    scOkay = 200,
    scCreated = 201,
    scAccepted = 202,
    scNonAuthoritativeInformation = 203,
    scNoContent = 204,
    scResetContent = 205,
    scPartialContent = 206,
    scMultiStatus = 207,     /**< RFC2518 section 10.2 / RFC4918 */
    scAlreadyReported = 208, /**< RFC5842 */
    scImUsed = 226,          /**< RFC3229 */
    scMultipleChoices = 300,
    scMovedPermanently = 301,
    scFound = 302,
    scSeeOther = 303,
    scNotModified = 304,
    scUseProxy = 305,
    scTemporaryRedirect = 307,
    scPermanentRedirect = 308, /**< RFC7538 */
    scBadRequest = 400,
    scUnauthorized = 401,
    scPaymentRequired = 402,
    scForbidden = 403,
    scNotFound = 404,
    scMethodNotAllowed = 405,
    scNotAcceptable = 406,
    scProxyAuthenticationRequired = 407,
    scRequestTimeout = 408,
    scConflict = 409,
    scGone = 410,
    scLengthRequired = 411,
    scPreconditionFailed = 412,
    scContentTooLarge = 413,
    scUriTooLong = 414,
    scUnsupportedMediaType = 415,
    scRequestedRangeNotSatisfied = 416,
    scExpectationFailed = 417,
    scMisdirectedRequest = 421,     /**< RFC7540 section 9.1.2 */
    scUnprocessableEntity = 422,    /**< RFC2518 section 10.3 / RFC4918 */
    scLocked = 423,                 /**< RFC2518 section 10.4 / RFC4918 */
    scFailedDependency = 424,       /**< RFC2518 section 10.5 / RFC4918 */
    scUpgradeRequired = 426,
    scPreconditionRequired = 428,   /**< RFC6585 */
    scTooManyRequests = 429,        /**< RFC6585 */
    scRequestHeaderFieldsTooLarge = 431, /**< RFC6585 */
    scUnavailableForLegalReasons = 451, /**< RFC7725 */
    scInternalServerError = 500,
    scNotImplemented = 501,
    scBadGateway = 502,
    scServiceUnavailable = 503,
    scGatewayTimeout = 504,
    scHttpVersionNotSupported = 505,
    scVariantAlsoNegotiates = 506,  /**< RFC2295 */
    scInsufficientStorage = 507,    /**< RFC2518 section 10.6 / RFC4918 */
    scLoopDetected = 508,           /**< RFC5842 */
    scNotExtended = 510,            /**< RFC2774 */
    scNetworkAuthenticationRequired = 511, /**< RFC6585 */

    // The 6xx codes below are for internal use only: Bad requests result
    // in scBadRequest; bad responses in scGatewayTimeout.

    scInvalidHeader = 600,          /**< Squid header parsing error */
    scHeaderTooLarge = 601         /* Header too large to process */
} StatusCode;

const char *StatusCodeString(const Http::StatusCode status);
/// whether this is an informational 1xx response status code
inline bool Is1xx(const int sc) { return scContinue <= sc && sc < scOkay; }
/// whether this is a client error 4xx response status code
inline bool Is4xx(const int sc) { return scBadRequest <= sc && sc < scInternalServerError; }
/// whether this response status code prohibits sending Content-Length
inline bool ProhibitsContentLength(const StatusCode sc) { return sc == scNoContent || Is1xx(sc); }
/// whether to send the request to another peer based on the current response status code
bool IsReforwardableStatus(StatusCode);

} // namespace Http

#endif /* _SQUID_SRC_HTTP_STATUSCODE_H */

