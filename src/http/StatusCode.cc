/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Debug.h"
#include "http/StatusCode.h"

const char *
Http::StatusCodeString(const Http::StatusCode status)
{
    switch (status) {

    // 000
    case Http::scNone:
        return "Init";      /* we init .status with code 0 */
        break;

    // 100-199
    case Http::scContinue:
        return "Continue";
        break;

    case Http::scSwitchingProtocols:
        return "Switching Protocols";
        break;

    case Http::scProcessing:
        return "Processing";
        break;

    case Http::scEarlyHints: // 103
        return "Early Hints";
        break;

    // 200-299
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

    case Http::scAlreadyReported:
        return "Already Reported";
        break;

    case Http::scImUsed:
        return "IM Used";
        break;

    // 300-399
    case Http::scMultipleChoices:
        return "Multiple Choices";
        break;

    case Http::scMovedPermanently:
        return "Moved Permanently";
        break;

    case Http::scFound:
        return "Found";
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

    // 400-499
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
        return "Request Timeout";
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

    case Http::scPayloadTooLarge:
        return "Payload Too Large";
        break;

    case Http::scUriTooLong:
        return "URI Too Long";
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

    case Http::scMisdirectedRequest:
        return "Misdirected Request";
        break;

    case Http::scUnprocessableEntity:
        return "Unprocessable Entity";
        break;

    case Http::scLocked:
        return "Locked";
        break;

    case Http::scFailedDependency:
        return "Failed Dependency";
        break;

    case Http::scUpgradeRequired:
        return "Upgrade Required";
        break;

    case Http::scPreconditionRequired:
        return "Precondition Required";
        break;

    case Http::scTooManyRequests:
        return "Too Many Requests";
        break;

    case Http::scRequestHeaderFieldsTooLarge:
        return "Request Header Fields Too Large";
        break;

    case scUnavailableForLegalReasons:
        return "Unavailable For Legal Reasons";
        break;

    // 500-599
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

    case Http::scGatewayTimeout:
        return "Gateway Timeout";
        break;

    case Http::scHttpVersionNotSupported:
        return "HTTP Version not supported";
        break;

    case Http::scVariantAlsoNegotiates:
        return "Variant Also Negotiates";
        break;

    case Http::scInsufficientStorage:
        return "Insufficient Storage";
        break;

    case Http::scLoopDetected:
        return "Loop Detected";
        break;

    case Http::scNotExtended:
        return "Not Extended";
        break;

    case Http::scNetworkAuthenticationRequired:
        return "Network Authentication Required";
        break;

    // 600+
    case Http::scInvalidHeader:
    case Http::scHeaderTooLarge:
    // fall through to default.

    default:
        debugs(57, 3, "Unassigned HTTP status code: " << status);
    }
    return "Unassigned";
}

