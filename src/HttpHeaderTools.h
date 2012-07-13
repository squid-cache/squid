#ifndef SQUID_HTTPHEADERTOOLS_H
#define SQUID_HTTPHEADERTOOLS_H

#if HAVE_MAP
#include <map>
#endif
#if HAVE_STRING
#include <string>
#endif

class acl_access;
struct _header_mangler {
    acl_access *access_list;
    char *replacement;
};
typedef struct _header_mangler header_mangler;

class StoreEntry;

/// A collection of header_mangler objects for a given message kind.
class HeaderManglers
{
public:
    HeaderManglers();
    ~HeaderManglers();

    /// returns a header mangler for field e or nil if none was specified
    const header_mangler *find(const HttpHeaderEntry &e) const;

    /// returns a mangler for the named header (known or custom)
    header_mangler *track(const char *name);

    /// updates mangler for the named header with a replacement value
    void setReplacement(const char *name, const char *replacementValue);

    /// report the *_header_access part of the configuration
    void dumpAccess(StoreEntry *entry, const char *optionName) const;
    /// report the *_header_replace part of the configuration
    void dumpReplacement(StoreEntry *entry, const char *optionName) const;

private:
    /// a name:mangler map; optimize: use unordered map or some such
    typedef std::map<std::string, header_mangler> ManglersByName;

    /// one mangler for each known header
    header_mangler known[HDR_ENUM_END];

    /// one mangler for each custom header
    ManglersByName custom;

    /// configured if some mangling ACL applies to all header names
    header_mangler all;

private:
    /* not implemented */
    HeaderManglers(const HeaderManglers &);
    HeaderManglers &operator =(const HeaderManglers &);
};
#endif
