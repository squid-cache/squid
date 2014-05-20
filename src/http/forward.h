#ifndef SQUID_SRC_HTTP_FORWARD_H
#define SQUID_SRC_HTTP_FORWARD_H

#include "http/one/forward.h"

// TODO move these classes into Http namespace
class HttpRequestMethod;
typedef RefCount<HttpRequestMethod> HttpRequestMethodPointer;

class HttpRequest;
typedef RefCount<HttpRequest> HttpRequestPointer;

class HttpReply;
typedef RefCount<HttpReply> HttpReplyPointer;

#endif /* SQUID_SRC_HTTP_FORWARD_H */
