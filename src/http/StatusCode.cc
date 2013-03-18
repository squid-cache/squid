#include "squid.h"
#include "Debug.h"
#include "http/StatusCode.h"

const char *
Http::StatusCodeString(const Http::StatusCode status)
{
    switch (status) {

    case Http::scNone:
        return "Init";		/* we init .status with code 0 */
        break;

    case Http::scContinue:
        return "Continue";
        break;

    case Http::scSwitchingProtocols:
        return "Switching Protocols";
        break;

    case Http::scOkay:
        return "OK";
        break;

    case Http::scCreated:
        return "Created";
        break;

    case Http::scAccepted:
        return "Accepted";
        break;

    case Http::scNonAuthoritativeInformation:
        return "Non-Authoritative Information";
        break;

    case Http::scNoContent:
        return "No Content";
        break;

    case Http::scResetContent:
        return "Reset Content";
        break;

    case Http::scPartialContent:
        return "Partial Content";
        break;

    case Http::scMultiStatus:
        return "Multi-Status";
        break;

    case Http::scMultipleChoices:
        return "Multiple Choices";
        break;

    case Http::scMovedPermanently:
        return "Moved Permanently";
        break;

    case Http::scMovedTemporarily:
        return "Moved Temporarily";
        break;

    case Http::scSeeOther:
        return "See Other";
        break;

    case Http::scNotModified:
        return "Not Modified";
        break;

    case Http::scUseProxy:
        return "Use Proxy";
        break;

    case Http::scTemporaryRedirect:
        return "Temporary Redirect";
        break;

    case Http::scPermanentRedirect:
        return "Permanent Redirect";
        break;

    case Http::scBadRequest:
        return "Bad Request";
        break;

    case Http::scUnauthorized:
        return "Unauthorized";
        break;

    case Http::scPaymentRequired:
        return "Payment Required";
        break;

    case Http::scForbidden:
        return "Forbidden";
        break;

    case Http::scNotFound:
        return "Not Found";
        break;

    case Http::scMethodNotAllowed:
        return "Method Not Allowed";
        break;

    case Http::scNotAcceptable:
        return "Not Acceptable";
        break;

    case Http::scProxyAuthenticationRequired:
        return "Proxy Authentication Required";
        break;

    case Http::scRequestTimeout:
        return "Request Time-out";
        break;

    case Http::scConflict:
        return "Conflict";
        break;

    case Http::scGone:
        return "Gone";
        break;

    case Http::scLengthRequired:
        return "Length Required";
        break;

    case Http::scPreconditionFailed:
        return "Precondition Failed";
        break;

    case Http::scRequestEntityTooLarge:
        return "Request Entity Too Large";
        break;

    case Http::scRequestUriTooLarge:
        return "Request-URI Too Large";
        break;

    case Http::scUnsupportedMediaType:
        return "Unsupported Media Type";
        break;

    case Http::scRequestedRangeNotSatisfied:
        return "Requested Range Not Satisfiable";
        break;

    case Http::scExpectationFailed:
        return "Expectation Failed";
        break;

    case Http::scInternalServerError:
        return "Internal Server Error";
        break;

    case Http::scNotImplemented:
        return "Not Implemented";
        break;

    case Http::scBadGateway:
        return "Bad Gateway";
        break;

    case Http::scServiceUnavailable:
        return "Service Unavailable";
        break;

    case Http::scGateway_Timeout:
        return "Gateway Time-out";
        break;

    case Http::scHttpVersionNotSupported:
        return "HTTP Version not supported";
        break;

        // RFC 6585
    case Http::scPreconditionRequired: // 428
        return "Precondition Required";
        break;

    case Http::scTooManyFields: // 429
        return "Too Many Requests";
        break;

    case Http::scRequestHeaderFieldsTooLarge: // 431
        return "Request Header Fields Too Large";
        break;

    case Http::scNetworkAuthenticationRequired: // 511
        return "Network Authentication Required";
        break;

    default:
        debugs(57, 3, "Unknown HTTP status code: " << status);
        return "Unknown";
    }
}
