/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_PARSER_FORWARD_H
#define SQUID_PARSER_FORWARD_H

namespace Parser {
class Tokenizer;
class BinaryTokenizer;

// TODO: Move this declaration (to parser/Elements.h) if we need more like it.
/// thrown by modern "incremental" parsers when they need more data
class InsufficientInput {};
} // namespace Parser

#endif /* SQUID_PARSER_FORWARD_H */

