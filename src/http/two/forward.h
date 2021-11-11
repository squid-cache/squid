/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_TWO_FORWARD_H
#define SQUID_SRC_HTTP_TWO_FORWARD_H

#include "base/RefCount.h"

namespace Http {

/// Hypertext Transfer Protocol version 2 (HTTP/2.0)
namespace Two {

class FrameParser;
typedef RefCount<Http::Two::FrameParser> FrameParserPointer;

class StreamContext;
typedef RefCount<Http::Two::StreamContext> StreamContextPointer;

} // namespace Two
} // namespace Http

namespace Http2 = Http::Two;

#endif /* SQUID_SRC_HTTP_TWO_FORWARD_H */
