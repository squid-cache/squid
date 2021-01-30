/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_ONE_FORWARD_H
#define SQUID_SRC_HTTP_ONE_FORWARD_H

#include "base/RefCount.h"
#include "parser/forward.h"
#include "sbuf/forward.h"

namespace Http {
namespace One {

class Tokenizer;

class Parser;
typedef RefCount<Http::One::Parser> ParserPointer;

class TeChunkedParser;

class RequestParser;
typedef RefCount<Http::One::RequestParser> RequestParserPointer;

class ResponseParser;
typedef RefCount<Http::One::ResponseParser> ResponseParserPointer;

/// CRLF textual representation
const SBuf &CrLf();

using ::Parser::InsufficientInput;

} // namespace One
} // namespace Http

namespace Http1 = Http::One;

#endif /* SQUID_SRC_HTTP_ONE_FORWARD_H */

