/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_FORMAT_TOKEN_H
#define _SQUID_FORMAT_TOKEN_H

#include "format/ByteCode.h"
#include "proxyp/Elements.h"

/*
 * Squid configuration allows users to define custom formats in
 * several components.
 * - logging
 * - external ACL input
 * - deny page URL
 *
 * These enumerations and classes define the API for parsing of
 * format directives to define these patterns. Along with output
 * functionality to produce formatted buffers.
 */

namespace Format
{

class TokenTableEntry;

#define LOG_BUF_SZ (MAX_URL<<2)

// XXX: inherit from linked list
class Token
{
public:
    Token();
    ~Token();

    /// Initialize the format token registrations
    static void Init();

    /** parses a single token. Returns the token length in characters,
     * and fills in this item with the token information.
     * def is for sure null-terminated.
     */
    int parse(const char *def, enum Quoting *quote);

    ByteCode_t type;
    const char *label;
    struct {
        char *string;
        // TODO: Add ID caching for protocols other than PROXY protocol.
        /// the cached ID of the parsed header or zero
        ProxyProtocol::Two::FieldType headerId;

        struct {
            char *header;
            char *element;
            char separator;
        } header;
    } data;
    int widthMin; ///< minimum field width
    int widthMax; ///< maximum field width
    enum Quoting quote;
    bool left;
    bool space;
    bool zero;
    int divisor;    // class invariant: MUST NOT be zero.
    Token *next;    // TODO: move from linked list to array

private:
    const char *scanForToken(TokenTableEntry const table[], const char *cur);
};

} // namespace Format

#endif /* _SQUID_FORMAT_TOKEN_H */

