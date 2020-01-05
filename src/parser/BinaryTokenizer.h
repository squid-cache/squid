/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_PARSER_BINARYTOKENIZER_H
#define SQUID_SRC_PARSER_BINARYTOKENIZER_H

#include "ip/forward.h"
#include "parser/forward.h"
#include "sbuf/SBuf.h"

namespace Parser
{

class BinaryTokenizer;

/// enables efficient debugging with concise field names: Hello.version.major
class BinaryTokenizerContext
{
public:
    /// starts parsing named object
    explicit BinaryTokenizerContext(BinaryTokenizer &tk, const char *aName);
    ~BinaryTokenizerContext() { close(); }

    /// ends parsing named object; repeated calls OK
    inline void close();

    /// reports successful parsing of a named object and calls close()
    inline void success();

    BinaryTokenizer &tokenizer; ///< tokenizer being used for parsing
    const BinaryTokenizerContext * const parent; ///< enclosing context or nullptr
    const char *const name; ///< this context description or nullptr
    uint64_t start; ///< context parsing begins at this tokenizer position
};

/// Safely extracts byte-oriented (i.e., non-textual) fields from raw input.
/// Assume that the integers are stored in network byte order.
/// Supports commit points for atomic incremental parsing of multi-part fields.
/// Throws InsufficientInput when more input is needed to parse the next field.
/// Throws on errors.
class BinaryTokenizer
{
public:
    typedef ::Parser::InsufficientInput InsufficientInput;
    typedef uint64_t size_type; // enough for the largest supported offset

    BinaryTokenizer();
    explicit BinaryTokenizer(const SBuf &data, const bool expectMore = false);

    /// restart parsing from the very beginning
    /// this method is for using one BinaryTokenizer to parse independent inputs
    void reset(const SBuf &data, const bool expectMore);

    /// change input state without changing parsing state
    /// this method avoids append overheads during incremental parsing
    void reinput(const SBuf &data, const bool expectMore) { data_ = data; expectMore_ = expectMore; }

    /// make progress: future parsing failures will not rollback beyond this point
    void commit();

    /// resume [incremental] parsing from the last commit point
    void rollback();

    /// no more bytes to parse or skip
    bool atEnd() const;

    /// parse a single-byte unsigned integer
    uint8_t uint8(const char *description);

    /// parse a two-byte unsigned integer
    uint16_t uint16(const char *description);

    /// parse a three-byte unsigned integer (returned as uint32_t)
    uint32_t uint24(const char *description);

    /// parse a four-byte unsigned integer
    uint32_t uint32(const char *description);

    /// parse size consecutive bytes as an opaque blob
    SBuf area(uint64_t size, const char *description);

    /// interpret the next 4 bytes as a raw in_addr structure
    Ip::Address inet4(const char *description);

    /// interpret the next 16 bytes as a raw in6_addr structure
    Ip::Address inet6(const char *description);

    /*
     * Variable-length arrays (a.k.a. Pascal or prefix strings).
     * pstringN() extracts and returns N-bit length followed by length bytes
     */
    SBuf pstring8(const char *description); ///< up to 255 byte-long p-string
    SBuf pstring16(const char *description); ///< up to 64 KiB-long p-string
    SBuf pstring24(const char *description); ///< up to 16 MiB-long p-string!

    /// ignore the next size bytes
    void skip(uint64_t size, const char *description);

    /// the number of already parsed bytes
    uint64_t parsed() const { return parsed_; }

    /// yet unparsed bytes
    SBuf leftovers() const { return data_.substr(parsed_); }

    /// debugging helper for parsed multi-field structures
    void got(uint64_t size, const char *description) const;

    const BinaryTokenizerContext *context; ///< debugging: thing being parsed

protected:
    uint32_t octet();
    void want(uint64_t size, const char *description) const;
    void got(uint32_t value, uint64_t size, const char *description) const;
    void got(const SBuf &value, uint64_t size, const char *description) const;
    void got(const Ip::Address &value, uint64_t size, const char *description) const;
    void skipped(uint64_t size, const char *description) const;

private:
    template <class InAddr>
    Ip::Address inetAny(const char *description);

    SBuf data_;
    uint64_t parsed_; ///< number of data bytes parsed or skipped
    uint64_t syncPoint_; ///< where to re-start the next parsing attempt
    bool expectMore_; ///< whether more data bytes may arrive in the future
};

/* BinaryTokenizerContext */

inline
BinaryTokenizerContext::BinaryTokenizerContext(BinaryTokenizer &tk, const char *aName):
    tokenizer(tk),
    parent(tk.context),
    name(aName),
    start(tk.parsed())
{
    tk.context = this;
}

inline
void
BinaryTokenizerContext::close() {
    tokenizer.context = parent;
}

inline
void
BinaryTokenizerContext::success() {
    tokenizer.got(tokenizer.parsed() - start, "");
    close();
}

} /* namespace Parser */

#endif // SQUID_SRC_PARSER_BINARYTOKENIZER_H

