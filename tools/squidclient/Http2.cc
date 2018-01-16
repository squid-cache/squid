#include "squid.h"
#include "Http2.h"
#include "Parameters.h"

#include <sstream>

static const char *
frameType(uint8_t t)
{
    /*
   | DATA          | 0x0  | Section 6.1  |
   | HEADERS       | 0x1  | Section 6.2  |
   | PRIORITY      | 0x2  | Section 6.3  |
   | RST_STREAM    | 0x3  | Section 6.4  |
   | SETTINGS      | 0x4  | Section 6.5  |
   | PUSH_PROMISE  | 0x5  | Section 6.6  |
   | PING          | 0x6  | Section 6.7  |
   | GOAWAY        | 0x7  | Section 6.8  |
   | WINDOW_UPDATE | 0x8  | Section 6.9  |
   | CONTINUATION  | 0x9  | Section 6.10 |
    */
    switch(t)
    {
    case 0x0: return "DATA";
    case 0x1: return "HEADERS";
    case 0x2: return "PRIORITY";
    case 0x3: return "RST_STREAM";
    case 0x4: return "SETTINGS";
    case 0x5: return "PUSH_PROMISE";
    case 0x6: return "PING";
    case 0x7: return "GOAWAY";
    case 0x8: return "WINDOW_UPDATE";
    case 0x9: return "CONTINUATION";
    }
    return "[undefined]";
}

static std::string
frameFlag(uint8_t type, int8_t flags)
{
    std::ostringstream out;

    if (type == Http2::SETTINGS && (flags & Http2::FLAG_ACK))
        out << "SETTINGS:ACK ";

    else if (type == Http2::PING && (flags & Http2::FLAG_ACK))
        out << "PING:ACK ";

    else if ( /* not SETTINGS */ (flags & Http2::FLAG_END_STREAM))
        out << "END_STREAM ";

    if ((flags & Http2::FLAG_END_HEADERS))
        out << "END_HEADERS ";

    if ((flags & Http2::FLAG_PADDED))
        out << "PADDED ";

    if ((flags & Http2::FLAG_PRIORITY))
        out << "PRIORITY ";

    // any other value is undefined.
    if ((flags & 0xD2)) {
        out << "[" << (flags & 0xD2) << "] ";
    }

    return out.str();
}

static std::string
framPadDisplay(const Http2::FrameHeader *fh, uint8_t sz)
{
    std::ostringstream out;
    if ((fh->flags() & Http2::FLAG_PADDED)) {
        out << " pad=" << sz;
    }
    return out.str();
}

void
Http::Two::display(const uint8_t *buf, size_t len)
{
    size_t pos = 0;
    while (pos < len) {
        const Http2::FrameHeader *fh = reinterpret_cast<const Http2::FrameHeader*>(buf+pos);

        // frame header details
        debugVerbose(2, "Frame: type=" << frameType(fh->type()) <<
                     " stream=" << fh->streamId() <<
                     " flags=" << frameFlag(fh->type(), fh->flags()) <<
                     " length=" << fh->length() <<
                     framPadDisplay(fh, buf[sizeof(Http2::FrameHeader)])
                     );

        // DATA to be written to display
        switch (fh->type())
        {
        case Http2::DATA: {
            size_t offset = sizeof(Http2::FrameHeader);
            size_t length = fh->length();
            if (fh->flags() & Http2::FLAG_PADDED) {
                length = length - buf[offset] - 1;
                ++offset; // skip padding size octet
            }
            std::cout.write(reinterpret_cast<const char *>(&buf[sizeof(Http2::FrameHeader)]), fh->length());
            debugVerbose(2, ""); // so next frame details will start on new line.
        } break;

        // TODO decode and display HEADERS, CONTINUATION

        default:
            break; // ignore

        } // end switch

        pos += sizeof(Http2::FrameHeader) + fh->length();
    }
}
