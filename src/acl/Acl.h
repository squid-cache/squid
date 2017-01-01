/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACL_H
#define SQUID_ACL_H

#include "acl/forward.h"
#include "cbdata.h"
#include "defines.h"
#include "dlink.h"
#include "MemPool.h"
#include "SBufList.h"

#include <ostream>
#include <string>
#include <vector>

class ConfigParser;

typedef char ACLFlag;
// ACLData Flags
#define ACL_F_REGEX_CASE 'i'
#define ACL_F_NO_LOOKUP 'n'
#define ACL_F_STRICT 's'
#define ACL_F_END '\0'

/**
 * \ingroup ACLAPI
 * Used to hold a list of one-letter flags which can be passed as parameters
 * to acls  (eg '-i', '-n' etc)
 */
class ACLFlags
{
public:
    explicit ACLFlags(const ACLFlag flags[]) : supported_(flags), flags_(0) {}
    ACLFlags() : flags_(0) {}
    bool supported(const ACLFlag f) const; ///< True if the given flag supported
    void makeSet(const ACLFlag f) { flags_ |= flagToInt(f); } ///< Set the given flag
    void makeUnSet(const ACLFlag f) { flags_ &= ~flagToInt(f); } ///< Unset the given flag
    /// Return true if the given flag is set
    bool isSet(const ACLFlag f) const { return flags_ & flagToInt(f);}
    /// Parse optional flags given in the form -[A..Z|a..z]
    void parseFlags();
    const char *flagsStr() const; ///< Convert the flags to a string representation

private:
    /// Convert a flag to a 64bit unsigned integer.
    /// The characters from 'A' to 'z' represented by the values from 65 to 122.
    /// They are 57 different characters which can be fit to the bits of an 64bit
    /// integer.
    uint64_t flagToInt(const ACLFlag f) const {
        assert('A' <= f && f <= 'z');
        return ((uint64_t)1 << (f - 'A'));
    }

    std::string supported_; ///< The supported character flags
    uint64_t flags_; ///< The flags which is set
public:
    static const ACLFlag NoFlags[1]; ///< An empty flags list
};

/// A configurable condition. A node in the ACL expression tree.
/// Can evaluate itself in FilledChecklist context.
/// Does not change during evaluation.
/// \ingroup ACLAPI
class ACL
{

public:
    void *operator new(size_t);
    void operator delete(void *);

    static ACL *Factory(char const *);
    static void ParseAclLine(ConfigParser &parser, ACL ** head);
    static void Initialize();
    static ACL *FindByName(const char *name);

    ACL();
    explicit ACL(const ACLFlag flgs[]) : cfgline(NULL), next(NULL), flags(flgs), registered(false) {
        *name = 0;
    }
    virtual ~ACL();

    /// sets user-specified ACL name and squid.conf context
    void context(const char *name, const char *configuration);

    /// Orchestrates matching checklist against the ACL using match(),
    /// after checking preconditions and while providing debugging.
    /// Returns true if and only if there was a successful match.
    /// Updates the checklist state on match, async, and failure.
    bool matches(ACLChecklist *checklist) const;

    virtual ACL *clone() const = 0;

    /// parses node represenation in squid.conf; dies on failures
    virtual void parse() = 0;
    virtual char const *typeString() const = 0;
    virtual bool isProxyAuth() const;
    virtual SBufList dump() const = 0;
    virtual bool empty() const = 0;
    virtual bool valid() const;

    int cacheMatchAcl(dlink_list * cache, ACLChecklist *);
    virtual int matchForCache(ACLChecklist *checklist);

    virtual void prepareForUse() {}

    char name[ACL_NAME_SZ];
    char *cfgline;
    ACL *next; // XXX: remove or at least use refcounting
    ACLFlags flags; ///< The list of given ACL flags
    bool registered; ///< added to the global list of ACLs via aclRegister()

public:

    class Prototype
    {

    public:
        Prototype();
        Prototype(ACL const *, char const *);
        ~Prototype();
        static bool Registered(char const *);
        static ACL *Factory(char const *);

    private:
        ACL const *prototype;
        char const *typeString;

    private:
        static std::vector<Prototype const *> * Registry;
        static void *Initialized;
        typedef std::vector<Prototype const*>::iterator iterator;
        typedef std::vector<Prototype const*>::const_iterator const_iterator;
        void registerMe();
    };

private:
    /// Matches the actual data in checklist against this ACL.
    virtual int match(ACLChecklist *checklist) = 0; // XXX: missing const

    /// whether our (i.e. shallow) match() requires checklist to have a request
    virtual bool requiresRequest() const;
    /// whether our (i.e. shallow) match() requires checklist to have a reply
    virtual bool requiresReply() const;
};

/// \ingroup ACLAPI
typedef enum {
    // Authorization ACL result states
    ACCESS_DENIED,
    ACCESS_ALLOWED,
    ACCESS_DUNNO,

    // Authentication ACL result states
    ACCESS_AUTH_REQUIRED,    // Missing Credentials
} aclMatchCode;

/// \ingroup ACLAPI
/// ACL check answer; TODO: Rename to Acl::Answer
class allow_t
{
public:
    // not explicit: allow "aclMatchCode to allow_t" conversions (for now)
    allow_t(const aclMatchCode aCode, int aKind = 0): code(aCode), kind(aKind) {}

    allow_t(): code(ACCESS_DUNNO), kind(0) {}

    bool operator ==(const aclMatchCode aCode) const {
        return code == aCode;
    }

    bool operator !=(const aclMatchCode aCode) const {
        return !(*this == aCode);
    }

    bool operator ==(const allow_t allow) const {
        return code == allow.code && kind == allow.kind;
    }

    operator aclMatchCode() const {
        return code;
    }

    aclMatchCode code; ///< ACCESS_* code
    int kind; ///< which custom access list verb matched
};

inline std::ostream &
operator <<(std::ostream &o, const allow_t a)
{
    switch (a) {
    case ACCESS_DENIED:
        o << "DENIED";
        break;
    case ACCESS_ALLOWED:
        o << "ALLOWED";
        break;
    case ACCESS_DUNNO:
        o << "DUNNO";
        break;
    case ACCESS_AUTH_REQUIRED:
        o << "AUTH_REQUIRED";
        break;
    }
    return o;
}

/// \ingroup ACLAPI
class acl_proxy_auth_match_cache
{

public:
    MEMPROXY_CLASS(acl_proxy_auth_match_cache);
    dlink_node link;
    int matchrv;
    void *acl_data;
};

MEMPROXY_CLASS_INLINE(acl_proxy_auth_match_cache);

/// \ingroup ACLAPI
/// XXX: find a way to remove or at least use a refcounted ACL pointer
extern const char *AclMatchedName;  /* NULL */

#endif /* SQUID_ACL_H */

