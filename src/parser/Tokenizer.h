/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PARSER_TOKENIZER_H_
#define SQUID_PARSER_TOKENIZER_H_

#include "base/CharacterSet.h"
#include "SBuf.h"

/// Generic protocol-agnostic parsing tools
namespace Parser
{

/**
 * Lexical processor to tokenize a buffer.
 *
 * Allows arbitrary delimiters and token character sets to
 * be provided by callers.
 *
 * All methods start from the beginning of the input buffer.
 * Methods returning true consume bytes from the buffer.
 * Methods returning false have no side-effects.
 */
class Tokenizer
{
public:
    explicit Tokenizer(const SBuf &inBuf) : buf_(inBuf), parsed_(0) {}

    /// yet unparsed data
    SBuf buf() const { return buf_; }

    /// number of parsed bytes, including skipped ones
    SBuf::size_type parsedSize() const { return parsed_; }

    /// whether the end of the buffer has been reached
    bool atEnd() const { return buf_.isEmpty(); }

    /// the remaining unprocessed section of buffer
    const SBuf& remaining() const { return buf_; }

    /// reinitialize processing for a new buffer
    void reset(const SBuf &newBuf) { buf_ = newBuf; parsed_ = 0; }

    /** Basic strtok(3):
     *  Skips all leading delimiters (if any),
     *  extracts all characters up to the next delimiter (a token), and
     *  skips all trailing delimiters (at least one must be present).
     *
     *  Want to extract delimiters? Use prefix() instead.
     *
     *  Note that Tokenizer cannot tell whether the trailing delimiters will
     *  continue when/if more input data becomes available later.
     *
     * \return true if found a non-empty token followed by a delimiter
     */
    bool token(SBuf &returnedToken, const CharacterSet &delimiters);

    /** Extracts all sequential permitted characters up to an optional length limit.
     *
     *  Note that Tokenizer cannot tell whether the prefix will
     *  continue when/if more input data becomes available later.
     *
     * \retval true one or more characters were found, the sequence (string) is placed in returnedToken
     * \retval false no characters from the permitted set were found
     */
    bool prefix(SBuf &returnedToken, const CharacterSet &tokenChars, SBuf::size_type limit = SBuf::npos);

    /** skips a given character sequence (string)
     *
     * \return whether the exact character sequence was found and skipped
     */
    bool skip(const SBuf &tokenToSkip);

    /** skips a given single character
     *
     * \return whether the character was skipped
     */
    bool skip(const char tokenChar);

    /** Skips a single character from the set.
     *
     * \return whether a character was skipped
     */
    bool skipOne(const CharacterSet &discardables);

    /** Skips all sequential characters from the set, in any order.
     *
     * \returns the number of skipped characters
     */
    SBuf::size_type skipAll(const CharacterSet &discardables);

    /** Extracts an unsigned int64_t at the beginning of the buffer.
     *
     * strtoll(3)-alike function: tries to parse unsigned 64-bit integer
     * at the beginning of the parse buffer, in the base specified by the user
     * or guesstimated; consumes the parsed characters.
     *
     * \param result Output value. Not touched if parsing is unsuccessful.
     * \param base   Specify base to do the parsing in, with the same restrictions
     *               as strtoll. Defaults to 0 (meaning guess)
     *
     * \return whether the parsing was successful
     */
    bool int64(int64_t &result, int base = 0);

protected:
    SBuf consume(const SBuf::size_type n);
    SBuf::size_type success(const SBuf::size_type n);

private:
    SBuf buf_; ///< yet unparsed input
    SBuf::size_type parsed_; ///< bytes successfully parsed, including skipped
};

} /* namespace Parser */

#endif /* SQUID_PARSER_TOKENIZER_H_ */

