#ifndef SQUID_PARSER_TOKENIZER_H_
#define SQUID_PARSER_TOKENIZER_H_

#include "CharacterSet.h"
#include "SBuf.h"

namespace Parser {

class Tokenizer {
public:
   explicit Tokenizer(const SBuf &inBuf) : buf_(inBuf) {}

   bool atEnd() const { return !buf_.length(); }
   const SBuf& remaining() const { return buf_; }
   void reset(const SBuf &newBuf) { buf_ = newBuf; }

   /* The following methods start from the beginning of the input buffer.
    * They return true and consume parsed chars if a non-empty token is found.
    * Otherwise, they return false without any side-effects. */

   /** Basic strtok(3):
    *  Skips all leading delimiters (if any),
    *  accumulates all characters up to the first delimiter (a token), and
    *  skips all trailing delimiters (if any).
    *  Want to extract delimiters? Use three prefix() calls instead.
    */
   bool token(SBuf &returnedToken, const CharacterSet &whitespace);

   /// Accumulates all sequential permitted characters (a token).
   bool prefix(SBuf &returnedToken, const CharacterSet &tokenChars);

   /// Skips all sequential permitted characters (a token).
   bool skip(const CharacterSet &tokenChars);

   /// Skips a given token.
   bool skip(const SBuf &tokenToSkip);

   /// Skips a given character (a token).
   bool skip(const char tokenChar);

private:
   SBuf buf_; ///< yet unparsed input

   /// find the position of the first character in the set. Return npos if not found
   SBuf::size_type find_first_in (const CharacterSet &set);
   SBuf::size_type find_first_not_in (const CharacterSet &set);
};


} /* namespace Parser */
#endif /* SQUID_PARSER_TOKENIZER_H_ */
