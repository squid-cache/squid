#ifndef SQUID_SRC_HTTP_ONE_FORWARD_H
#define SQUID_SRC_HTTP_ONE_FORWARD_H

#include "base/RefCount.h"

namespace Http {
namespace One {

class Parser;
typedef RefCount<Http::One::Parser> ParserPointer;

class RequestParser;
typedef RefCount<Http::One::RequestParser> RequestParserPointer;

} // namespace One
} // namespace Http

namespace Http1 = Http::One;

#endif /* SQUID_SRC_HTTP_ONE_FORWARD_H */
