#ifndef _SQUID_SRC_HTTP_STATUSCODE_H
#define _SQUID_SRC_HTTP_STATUSCODE_H

namespace Http
{

/**
 * These basic HTTP reply status codes are defined by RFC 2616 unless otherwise stated.
 */
typedef enum {
    scNone = 0,
    scContinue = 100,
    scSwitchingProtocols = 101,
    scProcessing = 102,      /**< RFC2518 section 10.1 */
    scOkay = 200,
    scCreated = 201,
    scAccepted = 202,
    scNonAuthoritativeInformation = 203,
    scNoContent = 204,
    scResetContent = 205,
    scPartialContent = 206,
    scMultiStatus = 207,    /**< RFC2518 section 10.2 */
    scMultipleChoices = 300,
    scMovedPermanently = 301,
    scMovedTemporarily = 302,
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
    scRequestEntityTooLarge = 413,
    scRequestUriTooLarge = 414,
    scUnsupportedMediaType = 415,
    scRequestedRangeNotSatisfied = 416,
    scExpectationFailed = 417,
    scUnprocessableEntity = 422,    /**< RFC2518 section 10.3 */
    scLocked = 423,                  /**< RFC2518 section 10.4 */
    scFailedDependency = 424,       /**< RFC2518 section 10.5 */
    scPreconditionRequired = 428,   /**< RFC6585 */
    scTooManyFields = 429,       /**< RFC6585 */
    scRequestHeaderFieldsTooLarge = 431, /**< RFC6585 */
    scInternalServerError = 500,
    scNotImplemented = 501,
    scBadGateway = 502,
    scServiceUnavailable = 503,
    scGateway_Timeout = 504,
    scHttpVersionNotSupported = 505,
    scInsufficientStorage = 507,    /**< RFC2518 section 10.6 */
    scNetworkAuthenticationRequired = 511, /**< RFC6585 */

    // The 6xx codes below are for internal use only: Bad requests result
    // in scBadRequest; bad responses in scGateway_Timeout.

    scInvalidHeader = 600,          /**< Squid header parsing error */
    scHeaderTooLarge = 601         /* Header too large to process */
} StatusCode;

} // namespace Http

#endif /* _SQUID_SRC_HTTP_STATUSCODE_H */
