#include "squid.h"
#include "Debug.h"
#include "http/one/ResponseParser.h"
#include "http/ProtocolVersion.h"
#include "parser/Tokenizer.h"
#include "profiler/Profiler.h"
#include "SquidConfig.h"

const SBuf Http::One::ResponseParser::IcyMagic("ICY ");

Http1::Parser::size_type
Http::One::ResponseParser::firstLineSize() const
{
    Http1::Parser::size_type result = 0;

    switch (msgProtocol_.protocol)
    {
    case AnyP::PROTO_HTTP:
        result += Http1magic.length();
        break;
    case AnyP::PROTO_ICY:
        result += IcyMagic.length();
        break;
    default: // no other protocols supported
        return result;
    }
    // NP: the parser does not accept >2 DIGIT for version numbers
    if (msgProtocol_.minor >10)
        result += 2;
    else
        result += 1;

    result += 5; /* 5 octets in: SP status SP */
    result += reasonPhrase_.length();
    result += 2; /* CRLF terminator */
    return result;
}

// NP: we found the protocol version and consumed it already.
// just need the status code and reason phrase
const int
Http::One::ResponseParser::parseResponseStatusAndReason()
{
    if (buf_.isEmpty())
        return 0;

    ::Parser::Tokenizer tok(buf_);

    if (!completedStatus_) {
        debugs(74, 9, "seek status-code in: " << tok.remaining().substr(0,10) << "...");
        SBuf status;
        // status code is 3 DIGIT octets
        // NP: search space is >3 to get terminator character)
        if(!tok.prefix(status, CharacterSet::DIGIT, 4))
            return -1; // invalid status
        // NOTE: multiple SP or non-SP bytes between version and status code are invalid.
        if (tok.atEnd())
            return 0; // need more to be sure we have it all
        if(!tok.skip(' '))
            return -1; // invalid status, a single SP terminator required
        // NOTE: any whitespace after the single SP is part of the reason phrase.

        debugs(74, 6, "found string status-code=" << status);

        // get the actual numeric value of the 0-3 digits we found
        ::Parser::Tokenizer t2(status);
        int64_t statusValue;
        if (!t2.int64(statusValue))
            return -1; // ouch. digits not forming a valid number?
        debugs(74, 6, "found int64 status-code=" << statusValue);
        if (statusValue < 0 || statusValue > 999)
            return -1; // ouch. digits not within valid status code range.

        statusCode_ = static_cast<Http::StatusCode>(statusValue);

        buf_ = tok.remaining(); // resume checkpoint
        completedStatus_ = true;
    }

    if (tok.atEnd())
        return 0; // need more to be sure we have it all

    /* RFC 7230 says we SHOULD ignore the reason phrase content
     * but it has a definite valid vs invalid character set.
     * We interpret the SHOULD as ignoring absence and syntax, but
     * producing an error if it contains an invalid octet.
     */

    debugs(74, 9, "seek reason-phrase in: " << tok.remaining().substr(0,50) << "...");

    // if we got here we are still looking for reason-phrase bytes
    static const CharacterSet phraseChars = CharacterSet::WSP + CharacterSet::VCHAR + CharacterSet::OBSTEXT;
    tok.prefix(reasonPhrase_, phraseChars); // optional, no error if missing
    tok.skip('\r'); // optional trailing CR

    if (tok.atEnd())
        return 0; // need more to be sure we have it all

    // LF existence matters
    if (!tok.skip('\n')) {
        reasonPhrase_.clear();
        return -1; // found invalid characters in the phrase
    }

    debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
    buf_ = tok.remaining(); // resume checkpoint
    return 1;
}

const int
Http::One::ResponseParser::parseResponseFirstLine()
{
    ::Parser::Tokenizer tok(buf_);

    if (msgProtocol_.protocol != AnyP::PROTO_NONE) {
        debugs(74, 6, "continue incremental parse for " << msgProtocol_);
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        // we already found the magic, but not the full line. keep going.
        return parseResponseStatusAndReason();

    } else if (tok.skip(Http1magic)) {
        debugs(74, 6, "found prefix magic " << Http1magic);
        // HTTP Response status-line parse

        // magic contains major version, still need to find minor
        SBuf verMinor;
        // NP: we limit to 2-digits for speed, there really is no limit
        // XXX: the protocols we accept dont have valid versions > 10 anyway
        if (!tok.prefix(verMinor, CharacterSet::DIGIT, 2))
            return -1; // invalid version minor code
        if (tok.atEnd())
            return 0; // need more to be sure we have it all
        if(!tok.skip(' '))
            return -1; // invalid version, a single SP terminator required

        debugs(74, 6, "found string version-minor=" << verMinor);

        // get the actual numeric value of the 0-3 digits we found
        ::Parser::Tokenizer t2(verMinor);
        int64_t tvm = 0;
        if (!t2.int64(tvm))
            return -1; // ouch. digits not forming a valid number?
        msgProtocol_.minor = static_cast<unsigned int>(tvm);

        msgProtocol_.protocol = AnyP::PROTO_HTTP;
        msgProtocol_.major = 1;

        debugs(74, 6, "found version=" << msgProtocol_);

        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        buf_ = tok.remaining(); // resume checkpoint
        return parseResponseStatusAndReason();

    } else if (tok.skip(IcyMagic)) {
        debugs(74, 6, "found prefix magic " << IcyMagic);
        // ICY Response status-line parse (same as HTTP/1 after the magic version)
        msgProtocol_.protocol = AnyP::PROTO_ICY;
        // NP: ICY has no /major.minor details
        debugs(74, DBG_DATA, "parse remaining buf={length=" << tok.remaining().length() << ", data='" << tok.remaining() << "'}");
        buf_ = tok.remaining(); // resume checkpoint
        return parseResponseStatusAndReason();

    } else if (buf_.length() > Http1magic.length() && buf_.length() > IcyMagic.length()) {
        debugs(74, 2, "unknown/missing prefix magic. Interpreting as HTTP/0.9");
        // found something that looks like an HTTP/0.9 response
        // Gateway/Transform it into HTTP/1.1
        msgProtocol_ = Http::ProtocolVersion(1,1);
        // XXX: probably should use version 0.9 here and upgrade on output,
        // but the old code did 1.1 transformation now.
        statusCode_ = Http::scOkay;
        static const SBuf gatewayPhrase("Gatewaying");
        reasonPhrase_ = gatewayPhrase;
        static const SBuf fakeHttpMimeBlock("X-Transformed-From: HTTP/0.9\r\n"
                                            /* Server: visible_appname_string */
                                            "Mime-Version: 1.0\r\n"
                                            /* Date: squid_curtime */
                                            "Expires: -1\r\n\r\n");
        mimeHeaderBlock_ = fakeHttpMimeBlock;
        parsingStage_ = HTTP_PARSE_DONE;
        return 1; // no more parsing
    }

    return 0; // need more to parse anything.
}

bool
Http::One::ResponseParser::parse(const SBuf &aBuf)
{
    buf_ = aBuf;
    debugs(74, DBG_DATA, "Parse buf={length=" << aBuf.length() << ", data='" << aBuf << "'}");

    // stage 1: locate the status-line
    if (parsingStage_ == HTTP_PARSE_NONE) {
        // RFC 7230 explicitly states whether garbage whitespace is to be handled
        // at each point of the message framing boundaries.
        // It omits mentioning garbage prior to HTTP Responses.
        // Therefore, if we receive anything at all treat it as Response message.
        if (!buf_.isEmpty())
            parsingStage_ = HTTP_PARSE_FIRST;
        else
            return false;
    }

    // stage 2: parse the status-line
    if (parsingStage_ == HTTP_PARSE_FIRST) {
        PROF_start(HttpParserParseReplyLine);

        int retcode = parseResponseFirstLine();

        // first-line (or a look-alike) found successfully.
        if (retcode > 0)
            parsingStage_ = HTTP_PARSE_MIME;
        debugs(74, 5, "status-line: retval " << retcode);
        debugs(74, 5, "status-line: proto " << msgProtocol_);
        debugs(74, 5, "status-line: status-code " << statusCode_);
        debugs(74, 5, "status-line: reason-phrase " << reasonPhrase_);
        debugs(74, 5, "Parser: bytes processed=" << (aBuf.length()-buf_.length()));
        PROF_stop(HttpParserParseReplyLine);

        // syntax errors already
        if (retcode < 0) {
            parsingStage_ = HTTP_PARSE_DONE;
            statusCode_ = Http::scInvalidHeader;
            return false;
        }
    }

    // stage 3: locate the mime header block
    if (parsingStage_ == HTTP_PARSE_MIME) {
        if (!findMimeBlock("Response", Config.maxReplyHeaderSize))
            return false;
    }

    return !needsMoreData();
}
