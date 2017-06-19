/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_ONE_PARSER_H
#define _SQUID_SRC_HTTP_ONE_PARSER_H

#include "anyp/ProtocolVersion.h"
#include "http/one/forward.h"
#include "http/StatusCode.h"
#include "sbuf/SBuf.h"

namespace Http {
namespace One {

// Parser states
enum ParseState {
    HTTP_PARSE_NONE,      ///< initialized, but nothing usefully parsed yet
    HTTP_PARSE_FIRST,     ///< HTTP/1 message first-line
    HTTP_PARSE_CHUNK_SZ,  ///< HTTP/1.1 chunked encoding chunk-size
    HTTP_PARSE_CHUNK_EXT, ///< HTTP/1.1 chunked encoding chunk-ext
    HTTP_PARSE_CHUNK,     ///< HTTP/1.1 chunked encoding chunk-data
    HTTP_PARSE_MIME,      ///< HTTP/1 mime-header block
    HTTP_PARSE_DONE       ///< parsed a message header, or reached a terminal syntax error
};

/** HTTP/1.x protocol parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major CRLF delimited segments of an HTTP/1 procotol message:
 *
 * \item first-line (request-line / simple-request / status-line)
 * \item mime-header 0*( header-name ':' SP field-value CRLF)
 */
class Parser : public RefCountable
{
public:
    typedef SBuf::size_type size_type;

    Parser() : parseStatusCode(Http::scNone), parsingStage_(HTTP_PARSE_NONE), hackExpectsMime_(false) {}
    virtual ~Parser() {}

    /// Set this parser back to a default state.
    /// Will DROP any reference to a buffer (does not free).
    virtual void clear() = 0;

    /// attempt to parse a message from the buffer
    /// \retval true if a full message was found and parsed
    /// \retval false if incomplete, invalid or no message was found
    virtual bool parse(const SBuf &aBuf) = 0;

    /** Whether the parser is waiting on more data to complete parsing a message.
     * Use to distinguish between incomplete data and error results
     * when parse() returns false.
     */
    bool needsMoreData() const {return parsingStage_!=HTTP_PARSE_DONE;}

    /// size in bytes of the first line including CRLF terminator
    virtual size_type firstLineSize() const = 0;

    /// size in bytes of the message headers including CRLF terminator(s)
    /// but excluding first-line bytes
    size_type headerBlockSize() const {return mimeHeaderBlock_.length();}

    /// size in bytes of HTTP message block, includes first-line and mime headers
    /// excludes any body/entity/payload bytes
    /// excludes any garbage prefix before the first-line
    size_type messageHeaderSize() const {return firstLineSize() + headerBlockSize();}

    /// buffer containing HTTP mime headers, excluding message first-line.
    SBuf mimeHeader() const {return mimeHeaderBlock_;}

    /// the protocol label for this message
    const AnyP::ProtocolVersion & messageProtocol() const {return msgProtocol_;}

    /**
     * Scan the mime header block (badly) for a header with the given name.
     *
     * BUG: omits lines when searching for headers with obs-fold or multiple entries.
     *
     * BUG: limits output to just 1KB when Squid accepts up to 64KB line length.
     *
     * \return A pointer to a field-value of the first matching field-name, or NULL.
     */
    char *getHeaderField(const char *name);

    /// the remaining unprocessed section of buffer
    const SBuf &remaining() const {return buf_;}

    /**
     * HTTP status code resulting from the parse process.
     * to be used on the invalid message handling.
     *
     * Http::scNone indicates incomplete parse,
     * Http::scOkay indicates no error,
     * other codes represent a parse error.
     */
    Http::StatusCode parseStatusCode;

    /// Whitespace between regular protocol elements.
    /// Seen in RFCs as OWS, RWS, BWS, SP/HTAB but may be "relaxed" by us.
    /// See also: DelimiterCharacters().
    static const CharacterSet &WhitespaceCharacters();

    /// Whitespace between protocol elements in restricted contexts like
    /// request line, status line, asctime-date, and credentials
    /// Seen in RFCs as SP but may be "relaxed" by us.
    /// See also: WhitespaceCharacters().
    /// XXX: Misnamed and overused.
    static const CharacterSet &DelimiterCharacters();

protected:
    /**
     * detect and skip the CRLF or (if tolerant) LF line terminator
     * consume from the tokenizer.
     *
     * throws if non-terminator is detected.
     * \retval true only if line terminator found.
     * \retval false incomplete or missing line terminator, need more data.
     */
    bool skipLineTerminator(Http1::Tokenizer &tok) const;

    /**
     * Scan to find the mime headers block for current message.
     *
     * \retval true   If mime block (or a blocks non-existence) has been
     *                identified accurately within limit characters.
     *                mimeHeaderBlock_ has been updated and buf_ consumed.
     *
     * \retval false  An error occured, or no mime terminator found within limit.
     */
    bool grabMimeBlock(const char *which, const size_t limit);

    /// RFC 7230 section 2.6 - 7 magic octets
    static const SBuf Http1magic;

    /// bytes remaining to be parsed
    SBuf buf_;

    /// what stage the parser is currently up to
    ParseState parsingStage_;

    /// what protocol label has been found in the first line (if any)
    AnyP::ProtocolVersion msgProtocol_;

    /// buffer holding the mime headers (if any)
    SBuf mimeHeaderBlock_;

    /// Whether the invalid HTTP as HTTP/0.9 hack expects a mime header block
    bool hackExpectsMime_;

private:
    void cleanMimePrefix();
    void unfoldMime();
};

/// skips and, if needed, warns about RFC 7230 BWS ("bad" whitespace)
/// \returns true (always; unlike all the skip*() functions)
bool ParseBws(Tokenizer &tok);

/// the right debugs() level for logging HTTP violation messages
int ErrorLevel();

} // namespace One
} // namespace Http

#endif /*  _SQUID_SRC_HTTP_ONE_PARSER_H */

