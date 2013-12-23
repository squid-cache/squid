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

class Http1Parser;
typedef RefCount<Http1Parser> Http1ParserPointer;

//class ParserBase;
//typedef RefCount<Http::ParserBase> HttpParserPointer;

} // namespace Http

#endif /* SQUID_SRC_HTTP_FORWARD_H */
