/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PARSER_TOKENIZER_H_
#define SQUID_PARSER_TOKENIZER_H_

#include "base/CharacterSet.h"
#include "sbuf/SBuf.h"

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
    void reset(const SBuf &newBuf) { undoParse(newBuf, 0); }

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

    /** Extracts all sequential permitted characters up to an optional length limit.
     * Operates on the trailing end of the buffer.
     *
     *  Note that Tokenizer cannot tell whether the buffer will
     *  gain more data when/if more input becomes available later.
     *
     * \retval true one or more characters were found, the sequence (string) is placed in returnedToken
     * \retval false no characters from the permitted set were found
     */
    bool suffix(SBuf &returnedToken, const CharacterSet &tokenChars, SBuf::size_type limit = SBuf::npos);

    /** skips a given suffix character sequence (string)
     * Operates on the trailing end of the buffer.
     *
     *  Note that Tokenizer cannot tell whether the buffer will
     *  gain more data when/if more input becomes available later.
     *
     * \return whether the exact character sequence was found and skipped
     */
    bool skipSuffix(const SBuf &tokenToSkip);

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

    /** Removes a single trailing character from the set.
     *
     * \return whether a character was removed
     */
    bool skipOneTrailing(const CharacterSet &discardables);

    /** Removes all sequential trailing characters from the set, in any order.
     *
     * \returns the number of characters removed
     */
    SBuf::size_type skipAllTrailing(const CharacterSet &discardables);

    /** Extracts an unsigned int64_t at the beginning of the buffer.
     *
     * strtoll(3)-alike function: tries to parse unsigned 64-bit integer
     * at the beginning of the parse buffer, in the base specified by the user
     * or guesstimated; consumes the parsed characters.
     *
     * \param result Output value. Not touched if parsing is unsuccessful.
     * \param base   Specify base to do the parsing in, with the same restrictions
     *               as strtoll. Defaults to 0 (meaning guess)
     * \param allowSign Whether to accept a '+' or '-' sign prefix.
     * \param limit  Maximum count of characters to convert.
     *
     * \return whether the parsing was successful
     */
    bool int64(int64_t &result, int base = 0, bool allowSign = true, SBuf::size_type limit = SBuf::npos);

    /*
     * The methods below mimic their counterparts documented above, but they
     * throw on errors, including InsufficientInput. The field description
     * parameter is used for error reporting and debugging.
     */

    /// prefix() wrapper but throws InsufficientInput if input contains
    /// nothing but the prefix (i.e. if the prefix is not "terminated")
    SBuf prefix(const char *description, const CharacterSet &tokenChars, SBuf::size_type limit = SBuf::npos);

    /// int64() wrapper but limited to unsigned decimal integers (for now)
    int64_t udec64(const char *description, SBuf::size_type limit = SBuf::npos);

protected:
    SBuf consume(const SBuf::size_type n);
    SBuf::size_type success(const SBuf::size_type n);
    SBuf consumeTrailing(const SBuf::size_type n);
    SBuf::size_type successTrailing(const SBuf::size_type n);

    /// reset the buffer and parsed stats to a saved checkpoint
    void undoParse(const SBuf &newBuf, SBuf::size_type cParsed) { buf_ = newBuf; parsed_ = cParsed; }

private:
    SBuf buf_; ///< yet unparsed input
    SBuf::size_type parsed_; ///< bytes successfully parsed, including skipped
};

} /* namespace Parser */

#endif /* SQUID_PARSER_TOKENIZER_H_ */

