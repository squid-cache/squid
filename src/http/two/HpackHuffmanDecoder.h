/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_TWO_HPACKHUFFMANDECODER_H
#define SQUID_SRC_HTTP_TWO_HPACKHUFFMANDECODER_H

#include "http/two/forward.h"
#include "mem/forward.h"
#include "sbuf/SBuf.h"

namespace Http {
namespace Two {

/**
 * The HPACK Huffman decoder context
 *
 * Implements RFC 7541 section Huffman
 */
class HpackHuffmanDecoder
{
public:
    bool decode(const SBuf &);

    SBuf output;
};

} // namespace Two
} // namespace Http

#endif /* SQUID_SRC_HTTP_TWO_HPACKHUFFMANDECODER_H */

