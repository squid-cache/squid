#ifndef SQUID_SRC_HTTP_FORWARD_H
#define SQUID_SRC_HTTP_FORWARD_H

#include "base/RefCount.h"

// TODO move these classes into Http namespace
class HttpRequestMethod;
typedef RefCount<HttpRequestMethod> HttpRequestMethodPointer;

class HttpRequest;
typedef RefCount<HttpRequest> HttpRequestPointer;

class HttpReply;
typedef RefCount<HttpReply> HttpReplyPointer;

namespace Http {

namespace One {
class RequestParser;
typedef RefCount<Http::One::RequestParser> RequestParserPointer;
} // namespace One

} // namespace Http

namespace Http1 = Http::One;

#endif /* SQUID_SRC_HTTP_FORWARD_H */
