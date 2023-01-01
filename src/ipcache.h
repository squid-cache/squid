/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_IPCACHE_H
#define _SQUID_IPCACHE_H

#include "base/CbcPointer.h"
#include "dns/forward.h"
#include "ip/Address.h"
#include <iosfwd>
#include <vector>

// The IPs the caller should not connect to are "bad". Other IPs are "good".

namespace Dns {

/// a CachedIps element
class CachedIp
{
public:
    explicit CachedIp(const Ip::Address &anIp): ip(anIp) {}

    /// whether the address is currently deemed problematic for any reason
    bool bad() const { return bad_; }

    /// mark the address as problematic; it might already be marked
    void markAsBad() { bad_ = true; }

    /// undo markAsBad()
    void forgetMarking() { bad_ = false; }

    Ip::Address ip;

private:
    bool bad_ = false; ///< whether the address is currently deemed problematic
};

class IpsIterator;
class GoodIpsIterator;
template <class Iterator>
class IpsSelector;

/// A small container of IP addresses with a "current good address" getter API.
/// Ignores Ip::Address port.
class CachedIps
{
public:
    /// whether we have at least one of the given IP addresses (ignoring ports)
    /// upon success, also sets *position if the `position` is not nil
    bool have(const Ip::Address &ip, size_t *position = nullptr) const;

    /// \returns a good address
    /// does not auto-rotate IPs but calling markAsBad() may change the answer
    const Ip::Address &current() const { return ips.at(goodPosition).ip; }

    bool empty() const noexcept { return ips.empty(); } ///< whether we cached no IPs at all
    size_t size() const noexcept { return ips.size(); } ///< all cached IPs
    size_t badCount() const noexcept { return badCount_; } ///< bad IPs

    inline IpsSelector<GoodIpsIterator> good() const; ///< good IPs
    inline IpsSelector<IpsIterator> goodAndBad() const; ///< all IPs

    typedef std::vector<CachedIp> Storage;
    const Storage &raw() const { return ips; } ///< all cached entries

    /// Finds and marks the given address as bad, adjusting current() if needed.
    /// Has no effect if the search fails or the found address is already bad.
    /// XXX: An attempt to mark the last good address erases all marks instead.
    /// XXX: It is impossible to successfully mark a single address as bad.
    void markAsBad(const char *name, const Ip::Address &ip);

    /// undo successful markAsBad()
    void forgetMarking(const char *name, const Ip::Address &ip);

    /// appends an IP address if we do not have() it already
    /// invalidates all iterators
    void pushUnique(const Ip::Address &ip);

    /// replace all info with the given (presumed good) IP address
    void reset(const Ip::Address &ip);

    /// prints current IP and other debugging information
    void reportCurrent(std::ostream &os) const;

private:
    bool seekNewGood(const char *name);
    void restoreGoodness(const char *name);

    // Memory- and speed-optimized for "a few (and usually just one)" IPs,
    // the vast majority of which are "good". The current implementation
    // does linear searches and often reallocs when adding IPs.
    Storage ips; ///< good and bad IPs

    template <class Iterator> friend class IpsSelector;
    size_t goodPosition = 0; ///< position of the IP returned by current()
    size_t badCount_ = 0; ///< number of IPs that are currently marked as bad
};

// The CachedIps class keeps meta information about individual IP addresses
// together with those IPs. CachedIps users do not care about caching details;
// they just want to iterate (a subset of) cached IPs. The IpsIterator and
// IpsSelector classes below are minimal helper classes that make cached IPs
// iteration easier, safer, and copy-free. See also: CachedIps::good().

/// Iterates over any (good and/or bad) IPs in CachedIps, in unspecified order.
class IpsIterator
{
public:
    typedef std::vector<CachedIp> Raw;
    typedef Raw::const_iterator RawIterator;

    // some of the standard iterator traits
    using iterator_category = std::forward_iterator_tag;
    using value_type = const Ip::Address;
    using pointer = value_type *;
    using reference = value_type &;

    IpsIterator(const Raw &raw, const size_t): position_(raw.cbegin()) {}
    // special constructor for end() iterator
    explicit IpsIterator(const Raw &raw): position_(raw.cend()) {}

    reference operator *() const { return position_->ip; }
    pointer operator ->() const { return &position_->ip; }

    IpsIterator& operator++() { ++position_; return *this; }
    IpsIterator operator++(int) { const auto oldMe = *this; ++(*this); return oldMe; }

    bool operator ==(const IpsIterator them) const { return position_ == them.position_; }
    bool operator !=(const IpsIterator them) const { return !(*this == them); }

private:
    RawIterator position_; ///< current iteration location
};

/// Iterates over good IPs in CachedIps, starting at the so called current one.
class GoodIpsIterator
{
public:
    typedef std::vector<CachedIp> Raw;
    typedef Raw::const_iterator RawIterator;

    // some of the standard iterator traits
    using iterator_category = std::forward_iterator_tag;
    using value_type = const Ip::Address;
    using pointer = value_type *;
    using reference = value_type &;

    GoodIpsIterator(const Raw &raw, const size_t currentPos): raw_(raw), position_(currentPos), processed_(0) { sync(); }
    // special constructor for end() iterator
    explicit GoodIpsIterator(const Raw &raw): raw_(raw), position_(0), processed_(raw.size()) {}

    reference operator *() const { return current().ip; }
    pointer operator ->() const { return &current().ip; }

    GoodIpsIterator& operator++() { next(); sync(); return *this; }
    GoodIpsIterator operator++(int) { const auto oldMe = *this; ++(*this); return oldMe; }

    bool operator ==(const GoodIpsIterator them) const { return processed_ == them.processed_; }
    bool operator !=(const GoodIpsIterator them) const { return !(*this == them); }

private:
    const CachedIp &current() const { return raw_[position_ % raw_.size()]; }
    void next() { ++position_; ++processed_; }
    void sync() { while (processed_ < raw_.size() && current().bad()) next(); }

    const Raw &raw_; ///< CachedIps being iterated
    size_t position_; ///< current iteration location, modulo raw.size()
    size_t processed_; ///< number of visited positions, including skipped ones
};

/// Makes "which IPs to iterate" decision explicit in range-based for loops.
/// Supported Iterator types are IpsIterator and GoodIpsIterator.
template <class Iterator>
class IpsSelector
{
public:
    explicit IpsSelector(const CachedIps &ips): ips_(ips) {}

    Iterator cbegin() const noexcept { return Iterator(ips_.raw(), ips_.goodPosition); }
    Iterator cend() const noexcept { return Iterator(ips_.raw()); }
    Iterator begin() const noexcept { return cbegin(); }
    Iterator end() const noexcept { return cend(); }

private:
    const CachedIps &ips_; ///< master IP storage we are wrapping
};

/// an interface for receiving IP::Addresses from nbgethostbyname()
class IpReceiver: public virtual CbdataParent
{
public:
    virtual ~IpReceiver() {}

    /// Called when nbgethostbyname() fully resolves the name.
    /// The `ips` may contain both bad and good IP addresses, but each good IP
    /// (if any) is guaranteed to had been previously reported via noteIp().
    virtual void noteIps(const CachedIps *ips, const LookupDetails &details) = 0;

    /// Called when/if nbgethostbyname() discovers a new good IP address.
    virtual void noteIp(const Ip::Address &) {}

    /// Called when/if nbgethostbyname() completes a single DNS lookup
    /// if called, called before all the noteIp() calls for that DNS lookup.
    virtual void noteLookup(const Dns::LookupDetails &) {}
};

/// initiate an (often) asynchronous DNS lookup; the `receiver` gets the results
void nbgethostbyname(const char *name, const CbcPointer<IpReceiver> &receiver);

} // namespace Dns

typedef Dns::CachedIps ipcache_addrs; ///< deprecated alias

typedef void IPH(const ipcache_addrs *, const Dns::LookupDetails &details, void *);

void ipcache_purgelru(void *);
void ipcache_nbgethostbyname(const char *name, IPH * handler, void *handlerData);
const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
void ipcacheInvalidate(const char *);
void ipcacheInvalidateNegative(const char *);
void ipcache_init(void);
void ipcacheMarkBadAddr(const char *name, const Ip::Address &);
void ipcacheMarkGoodAddr(const char *name, const Ip::Address &);
void ipcacheFreeMemory(void);
void ipcache_restart(void);
int ipcacheAddEntryFromHosts(const char *name, const char *ipaddr);

inline std::ostream &
operator <<(std::ostream &os, const Dns::CachedIps &ips)
{
    ips.reportCurrent(os);
    return os;
}

/* inlined implementations */

inline Dns::IpsSelector<Dns::GoodIpsIterator>
Dns::CachedIps::good() const
{
    return IpsSelector<GoodIpsIterator>(*this);
}

inline Dns::IpsSelector<Dns::IpsIterator>
Dns::CachedIps::goodAndBad() const
{
    return IpsSelector<IpsIterator>(*this);
}

#endif /* _SQUID_IPCACHE_H */

