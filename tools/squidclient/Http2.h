#ifndef SQUID_TOOLS_SQUIDCLIENT_HTTP2_H
#define SQUID_TOOLS_SQUIDCLIENT_HTTP2_H

#include "http/two/Frame.h"
#include "http/two/FrameType.h"

namespace Http
{
namespace Two
{

/// display some HTTP/2.0 input in human readable form
void display(const uint8_t *buf, size_t len);

} // namespace Two
} // namespace Http2

namespace Http2 = Http::Two;

#endif /* SQUID_TOOLS_SQUIDCLIENT_HTTP2_H */
