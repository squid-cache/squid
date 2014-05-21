#ifndef SQUID_PARSER_TOKENIZER_H_
#define SQUID_PARSER_TOKENIZER_H_

#include "base/CharacterSet.h"
#include "SBuf.h"

/// Generic protocol-agnostic parsing tools
namespace Parser {

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
class Tokenizer {
public:
   explicit Tokenizer(const SBuf &inBuf) : buf_(inBuf) {}

   /// whether the end of the buffer has been reached
   bool atEnd() const { return buf_.isEmpty(); }

   /// the remaining unprocessed section of buffer
   const SBuf& remaining() const { return buf_; }

   /// reinitialize processing for a new buffer
   void reset(const SBuf &newBuf) { buf_ = newBuf; }

   /** Basic strtok(3):
    *  Skips all leading delimiters (if any),
    *  accumulates all characters up to the next delimiter (a token), and
    *  skips all trailing delimiters (if any).
    *
    *  Want to extract delimiters? Use prefix() instead.
    */
   bool token(SBuf &returnedToken, const CharacterSet &delimiters);

   /** Accumulates all sequential permitted characters up to an optional length limit.
    *
    * \retval true one or more characters were found, the sequence (string) is placed in returnedToken
    * \retval false no characters from the permitted set were found
    */
   bool prefix(SBuf &returnedToken, const CharacterSet &tokenChars, SBuf::size_type limit = SBuf::npos);

   /** skips all sequential characters from the set, in any order
    *
    * \return whether one or more characters in the set were found
    */
   bool skip(const CharacterSet &tokenChars);

   /** skips a given character sequence (string)
    *
    * \return whether the exact character sequence was found and skipped
    */
   bool skip(const SBuf &tokenToSkip);

   /** skips a given single character
    *
    * \return whether the character was found and skipped
    */
   bool skip(const char tokenChar);

private:
   SBuf buf_; ///< yet unparsed input
};

} /* namespace Parser */

#endif /* SQUID_PARSER_TOKENIZER_H_ */
