/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_PARSER_H
#define _SQUID_SRC_HTTP_PARSER_H

#include "anyp/ProtocolVersion.h"
#include "http/one/forward.h"
#include "http/StatusCode.h"
#include "parser/forward.h"
#include "sbuf/SBuf.h"

namespace Http {

// Parser states
enum ParseState {
    HTTP_PARSE_NONE,      ///< initialized, but nothing usefully parsed yet
    HTTP_PARSE_FIRST,     ///< HTTP/1 message first-line
    HTTP_PARSE_CHUNK_SZ,  ///< HTTP/1.1 chunked encoding chunk-size
    HTTP_PARSE_CHUNK_EXT, ///< HTTP/1.1 chunked encoding chunk-ext
    HTTP_PARSE_CHUNK,     ///< HTTP/1.1 chunked encoding chunk-data
    HTTP_PARSE_MIME,      ///< HTTP/1 mime-header block
    HTTP_PARSE_FRAMES,    ///< HTTP/2 multiplexed frame sequence (after magic prefix)
    HTTP_PARSE_DONE       ///< parsed a message header, or reached a terminal syntax error
};

/** HTTP protocol parser
 *
 * Works on a raw character I/O buffer and tokenizes the content into
 * the major frames / segments of an HTTP protocol message.
 *
 * HTTP general design:
 *
 * Messages are formally a fixed sequence of segments
 *
 *  HTTP-message = start-line mime-header message-body
 *
 * \li start-line (request-line / simple-request / status-line)
 * \li mime-header 0*( header-name ':' SP field-value CRLF)
 *
 * The ordering of message segments is identical for all versions of HTTP.
 * How they are represented differs greatly.
 *
 * HTTP/1: RFC 7230 section 3
 * Segments are separated from each other by CRLF. There is no formal
 * separator between messages, the message endpoint is determined by which
 * segments exist and transfer encoding used.
 *
 * HTTP/2: RFC 7540 section 4
 * Segments are encapsulated in explicitly defined frames.
 * All frames begin with a fixed 9-octet header followed by a variable-
 * length payload containing all or some of the segment being sent.
 */
class Parser : public RefCountable
{
public:
    typedef SBuf::size_type size_type;
    typedef ::Parser::Tokenizer Tokenizer;

    Parser() = default;
    Parser(const Parser &) = default;
    Parser &operator =(const Parser &) = default;
    Parser(Parser &&) = default;
    Parser &operator =(Parser &&) = default;
    virtual ~Parser() {}

    /// Set this parser back to a default state.
    /// Will DROP any reference to a buffer (does not free).
    virtual void clear();

    /// attempt to parse a message (HTTP/1.x) or frame (HTTP/2) from the buffer
    /// \retval true if a full message/frame was found and parsed
    /// \retval false if incomplete, invalid or no message/frame was found
    virtual bool parse(const SBuf &aBuf) = 0;

    /** Whether the parser is waiting on more data to complete parsing.
     * Use to distinguish between incomplete data and error results
     * when parse() returns false.
     */
    bool needsMoreData() const {return parsingStage_!=HTTP_PARSE_DONE;}

    /**
     * For HTTP/1.x the size in bytes of the HTTP/1.x first line including CRLF terminator.
     *
     * For HTTP/2 the size of the frame header octets.
     */
    virtual size_type firstLineSize() const = 0;

    /**
     * For HTTP/0.9 returns 0.
     *
     * For HTTP/1.x the size in bytes of the message headers including CRLF
     * terminator(s) but excluding first-line bytes.
     *
     * For HTTP/2 returns 0.
     */
    size_type headerBlockSize() const {return mimeHeaderBlock_.length();}

    /**
     * For HTTP/0.9 returns size of first-line.
     *
     * For HTTP/1.x the size in bytes of the message block, includes first-line
     * and mime headers
     *
     * For HTTP/2 returns size of frame header octets.
     *
     * For all versions:
     * - excludes any body/entity/payload bytes
     * - excludes any garbage or prefix before the first-line
     */
    size_type messageHeaderSize() const {return firstLineSize() + headerBlockSize();}

    /// buffer containing HTTP mime headers, excluding message first-line.
    /// (HTTP/1.x only)
    SBuf mimeHeader() const {return mimeHeaderBlock_;}

    /// the protocol label for this message
    const AnyP::ProtocolVersion & messageProtocol() const {return msgProtocol_;}

    /**
     * Scan the HTTP/1 mime header block (badly) for a header with the given name.
     *
     * BUG: omits lines when searching for headers with obs-fold or multiple entries.
     *
     * BUG: limits output to just 1KB when Squid accepts up to 64KB line length.
     *
     * \return A pointer to a field-value of the first matching field-name, or NULL.
     */
    char *getHostHeaderField();

    /// the remaining unprocessed section of buffer
    const SBuf &remaining() const {return buf_;}

    // HTTP/2 detection methods

    /// RFC 7540 section 3.5 - 24 magic octets
    static const SBuf Http2magic; // should be protected, but some Servers use it

    /// whether the buffer content so far matches the HTTP/2 magic octets
    /// \returns true on partial matches. Use parseHttp2magicPrefix() for full match.
    bool incompleteHttp2magicPrefix() const {
        return memcmp(Http2magic.rawContent(),buf_.rawContent(),buf_.length())==0;
    }

    /**
     * Attempt to parse the magic octets of a new HTTP/2 connection
     *
     * Governed by:
     *  RFC 7540 section 3.5
     *
     * The return value tells you whether the parsing state fields are valid or
     * not. Use incompleteHttp2MagicPrefix() to test if the buffer needs more
     * octets to parse.
     *
     * \retval  true   buffer matches the magic octets.
     *                 member fields contain the request-line items for a
     *                 pseudo-HTTP/1 request
     *
     * \retval  false  buffer does not contain the full set of magic octets.
     */
    virtual bool parseHttp2magicPrefix(const SBuf &);

    /**
     * HTTP status code resulting from the parse process.
     * to be used on the invalid message handling.
     *
     * Http::scNone indicates incomplete parse,
     * Http::scOkay indicates no error,
     * other codes represent a parse error.
     */
    Http::StatusCode parseStatusCode = Http::scNone;

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
     * \throws exception on bad or InsuffientInput.
     * \retval true only if line terminator found.
     * \retval false incomplete or missing line terminator, need more data.
     */
    void skipLineTerminator(Tokenizer &) const;

    /**
     * Scan to find the mime headers block for current message.
     *
     * \retval true   If mime block (or a blocks non-existence) has been
     *                identified accurately within limit characters.
     *                mimeHeaderBlock_ has been updated and buf_ consumed.
     *
     * \retval false  An error occurred, or no mime terminator found within limit.
     */
    bool grabMimeBlock(const char *which, const size_t limit);

    /// RFC 7230 section 2.6 - 7 magic octets
    static const SBuf Http1magic;

    /// bytes remaining to be parsed
    SBuf buf_;

    /// what stage the parser is currently up to
    ParseState parsingStage_ = HTTP_PARSE_NONE;

    /// what protocol label has been found in the first line (if any)
    AnyP::ProtocolVersion msgProtocol_;

    /// buffer holding the mime headers (if any)
    SBuf mimeHeaderBlock_;

    /// Whether the invalid HTTP as HTTP/0.9 hack expects a mime header block
    bool hackExpectsMime_ = false;

private:
    void cleanMimePrefix();
    void unfoldMime();
};

/// skips and, if needed, warns about RFC 7230 BWS ("bad" whitespace)
/// \throws InsufficientInput when the end of BWS cannot be confirmed
void ParseBws(Parser::Tokenizer &);

/// the right debugs() level for logging HTTP violation messages
int ErrorLevel();

} // namespace Http

#endif /*  _SQUID_SRC_HTTP_PARSER_H */

