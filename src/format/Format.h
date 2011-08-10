#ifndef _SQUID_FORMAT_FORMAT_H
#define _SQUID_FORMAT_FORMAT_H

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

class AccessLogEntry;
class MemBuf;
class StoreEntry;

namespace Format
{

class Token;

// XXX: inherit from linked list
class Format
{
public:
    Format(const char *name);
    ~Format();

    /* very inefficent parser, but who cares, this needs to be simple */
    /* First off, let's tokenize, we'll optimize in a second pass.
     * A token can either be a %-prefixed sequence (usually a dynamic
     * token but it can be an escaped sequence), or a string. */
    bool parse(char *def);

    /// assemble the state information into a formatted line.
    void assemble(MemBuf &mb, AccessLogEntry *al, int logSequenceNumber) const;

    /// dump this whole list of formats into the provided StoreEntry
    void dump(StoreEntry * entry, const char *name);

    char *name;
    Token *format;
    Format *next;
};

} // namespace Format

#endif /* _SQUID_FORMAT_FORMAT_H */
