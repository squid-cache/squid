/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_STATUSCODE_H
#define SQUID_SRC_HTTP_STATUSCODE_H

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
    scProcessing = 102,
    scEarlyHints = 103,
    scUploadResumptionSupported = 104,
    scOkay = 200,
    scCreated = 201,
    scAccepted = 202,
    scNonAuthoritativeInformation = 203,
    scNoContent = 204,
    scResetContent = 205,
    scPartialContent = 206,
    scMultiStatus = 207,
    scAlreadyReported = 208,
    scImUsed = 226,
    scMultipleChoices = 300,
    scMovedPermanently = 301,
    scFound = 302,
    scSeeOther = 303,
    scNotModified = 304,
    scUseProxy = 305,
    scTemporaryRedirect = 307,
    scPermanentRedirect = 308,
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
    scMisdirectedRequest = 421,
    scUnprocessableEntity = 422,
    scLocked = 423,
    scFailedDependency = 424,
    scTooEarly = 425,
    scUpgradeRequired = 426,
    scPreconditionRequired = 428,
    scTooManyRequests = 429,
    scRequestHeaderFieldsTooLarge = 431,
    scUnavailableForLegalReasons = 451,
    scInternalServerError = 500,
    scNotImplemented = 501,
    scBadGateway = 502,
    scServiceUnavailable = 503,
    scGatewayTimeout = 504,
    scHttpVersionNotSupported = 505,
    scVariantAlsoNegotiates = 506,
    scInsufficientStorage = 507,
    scLoopDetected = 508,
    scNotExtended = 510,
    scNetworkAuthenticationRequired = 511,

    // The 6xx codes below are for internal use only: Bad requests result
    // in scBadRequest; bad responses in scGatewayTimeout.

    scInvalidHeader = 600, ///< Squid header parsing error
    scHeaderTooLarge = 601 ///< Header too large to process
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

#endif /* SQUID_SRC_HTTP_STATUSCODE_H */

