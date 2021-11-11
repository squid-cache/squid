#include "squid.h"
#include "http/two/FrameParser.h"
#include "http/two/FrameType.h"
#include "http/two/StreamContext.h"

void
Http::Two::StreamContext::update(const Http2::FrameParserPointer &hp)
{
    if (!id)
        id = hp->frameStreamId();
    assert(id == hp->frameStreamId());

    switch (hp->frameType())
    {
    case Http2::HEADERS:
        if (state != Http2::CLOSED_REMOTE)
            state = Http2::OPEN;
        headers.append(hp->framePayload());
        break;

    case Http2::RST_STREAM:
        state = Http2::CLOSED;
        writeQueue.clear();
        break;

    default: // no state change
        break;
    }
}
