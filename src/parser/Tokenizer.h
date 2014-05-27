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

   // return a copy the current contents of the parse buffer
   const SBuf buf() const { return buf_; }

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

   /** parse an unsigned int64_t at the beginning of the buffer
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

private:
   SBuf buf_; ///< yet unparsed input
};

} /* namespace Parser */

#endif /* SQUID_PARSER_TOKENIZER_H_ */
