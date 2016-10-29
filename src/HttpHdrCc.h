/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRCC_H
#define SQUID_HTTPHDRCC_H

#include "dlink.h"
#include "mem/forward.h"
#include "SquidString.h"
#include <iosfwd>

class Packable;

enum HttpHdrCcType : unsigned char {
    CC_PUBLIC = 0,
    CC_PRIVATE,
    CC_NO_CACHE,
    CC_NO_STORE,
    CC_NO_TRANSFORM,
    CC_MUST_REVALIDATE,
    CC_PROXY_REVALIDATE,
    CC_MAX_AGE,
    CC_S_MAXAGE,
    CC_MAX_STALE,
    CC_MIN_FRESH,
    CC_ONLY_IF_CACHED,
    CC_STALE_IF_ERROR,
    CC_IMMUTABLE, /* draft-mcmanus-immutable-00 */
    CC_OTHER,
    CC_ENUM_END /* also used to mean "invalid" */
};

/** Http Cache-Control header representation
 *
 * Store and parse the Cache-Control HTTP header.
 */
class HttpHdrCc
{
    MEMPROXY_CLASS(HttpHdrCc);

public:
    static const int32_t MAX_AGE_UNKNOWN=-1; //max-age is unset
    static const int32_t S_MAXAGE_UNKNOWN=-1; //s-maxage is unset
    static const int32_t MAX_STALE_UNKNOWN=-1; //max-stale is unset
    ///used to mark a valueless Cache-Control: max-stale directive, which instructs
    /// us to treat responses of any age as fresh
    static const int32_t MAX_STALE_ANY=0x7fffffff;
    static const int32_t STALE_IF_ERROR_UNKNOWN=-1; //stale_if_error is unset
    static const int32_t MIN_FRESH_UNKNOWN=-1; //min_fresh is unset

    HttpHdrCc() :
        mask(0), max_age(MAX_AGE_UNKNOWN), s_maxage(S_MAXAGE_UNKNOWN),
        max_stale(MAX_STALE_UNKNOWN), stale_if_error(STALE_IF_ERROR_UNKNOWN),
        min_fresh(MIN_FRESH_UNKNOWN) {}

    /// reset data-members to default state
    void clear();

    /// parse a header-string and fill in appropriate values.
    bool parse(const String & s);

    //manipulation for Cache-Control: public header
    bool hasPublic() const {return isSet(HttpHdrCcType::CC_PUBLIC);}
    bool Public() const {return isSet(HttpHdrCcType::CC_PUBLIC);}
    void Public(bool v) {setMask(HttpHdrCcType::CC_PUBLIC,v);}
    void clearPublic() {setMask(HttpHdrCcType::CC_PUBLIC,false);}

    //manipulation for Cache-Control: private header
    bool hasPrivate() const {return isSet(HttpHdrCcType::CC_PRIVATE);}
    const String &Private() const {return private_;}
    void Private(const String &v) {
        setMask(HttpHdrCcType::CC_PRIVATE,true);
        if (!v.size())
            return;
        // uses append for multi-line headers
        if (private_.size() > 0)
            private_.append(",");
        private_.append(v);
    }
    void clearPrivate() {setMask(HttpHdrCcType::CC_PRIVATE,false); private_.clean();}

    //manipulation for Cache-Control: no-cache header
    bool hasNoCache() const {return isSet(HttpHdrCcType::CC_NO_CACHE);}
    const String &noCache() const {return no_cache;}
    void noCache(const String &v) {
        setMask(HttpHdrCcType::CC_NO_CACHE,true);
        if (!v.size())
            return;
        // uses append for multi-line headers
        if (no_cache.size() > 0 && v.size() > 0)
            no_cache.append(",");
        no_cache.append(v);
    }
    void clearNoCache() {setMask(HttpHdrCcType::CC_NO_CACHE,false); no_cache.clean();}

    //manipulation for Cache-Control: no-store header
    bool hasNoStore() const {return isSet(HttpHdrCcType::CC_NO_STORE);}
    bool noStore() const {return isSet(HttpHdrCcType::CC_NO_STORE);}
    void noStore(bool v) {setMask(HttpHdrCcType::CC_NO_STORE,v);}
    void clearNoStore() {setMask(HttpHdrCcType::CC_NO_STORE,false);}

    //manipulation for Cache-Control: no-transform header
    bool hasNoTransform() const {return isSet(HttpHdrCcType::CC_NO_TRANSFORM);}
    bool noTransform() const {return isSet(HttpHdrCcType::CC_NO_TRANSFORM);}
    void noTransform(bool v) {setMask(HttpHdrCcType::CC_NO_TRANSFORM,v);}
    void clearNoTransform() {setMask(HttpHdrCcType::CC_NO_TRANSFORM,false);}

    //manipulation for Cache-Control: must-revalidate header
    bool hasMustRevalidate() const {return isSet(HttpHdrCcType::CC_MUST_REVALIDATE);}
    bool mustRevalidate() const {return isSet(HttpHdrCcType::CC_MUST_REVALIDATE);}
    void mustRevalidate(bool v) {setMask(HttpHdrCcType::CC_MUST_REVALIDATE,v);}
    void clearMustRevalidate() {setMask(HttpHdrCcType::CC_MUST_REVALIDATE,false);}

    //manipulation for Cache-Control: proxy-revalidate header
    bool hasProxyRevalidate() const {return isSet(HttpHdrCcType::CC_PROXY_REVALIDATE);}
    bool proxyRevalidate() const {return isSet(HttpHdrCcType::CC_PROXY_REVALIDATE);}
    void proxyRevalidate(bool v) {setMask(HttpHdrCcType::CC_PROXY_REVALIDATE,v);}
    void clearProxyRevalidate() {setMask(HttpHdrCcType::CC_PROXY_REVALIDATE,false);}

    //manipulation for Cache-Control: max-age header
    bool hasMaxAge() const {return isSet(HttpHdrCcType::CC_MAX_AGE);}
    int32_t maxAge() const { return max_age;}
    void maxAge(int32_t v) {setValue(max_age,v,HttpHdrCcType::CC_MAX_AGE); }
    void clearMaxAge() {setValue(max_age,MAX_AGE_UNKNOWN,HttpHdrCcType::CC_MAX_AGE,false);}

    //manipulation for Cache-Control: s-maxage header
    bool hasSMaxAge() const {return isSet(HttpHdrCcType::CC_S_MAXAGE);}
    int32_t sMaxAge() const { return s_maxage;}
    void sMaxAge(int32_t v) {setValue(s_maxage,v,HttpHdrCcType::CC_S_MAXAGE); }
    void clearSMaxAge() {setValue(s_maxage,MAX_AGE_UNKNOWN,HttpHdrCcType::CC_S_MAXAGE,false);}

    //manipulation for Cache-Control: max-stale header
    bool hasMaxStale() const {return isSet(HttpHdrCcType::CC_MAX_STALE);}
    int32_t maxStale() const { return max_stale;}
    // max-stale has a special value (MAX_STALE_ANY) which correspond to having
    // the directive without a numeric specification, and directs to consider the object
    // as always-expired.
    void maxStale(int32_t v) {setValue(max_stale,v,HttpHdrCcType::CC_MAX_STALE);}
    void clearMaxStale() {setValue(max_stale,MAX_STALE_UNKNOWN,HttpHdrCcType::CC_MAX_STALE,false);}

    //manipulation for Cache-Control:min-fresh header
    bool hasMinFresh() const {return isSet(HttpHdrCcType::CC_MIN_FRESH);}
    int32_t minFresh() const { return min_fresh;}
    void minFresh(int32_t v) {if (v < 0) return; setValue(min_fresh,v,HttpHdrCcType::CC_MIN_FRESH); }
    void clearMinFresh() {setValue(min_fresh,MIN_FRESH_UNKNOWN,HttpHdrCcType::CC_MIN_FRESH,false);}

    //manipulation for Cache-Control: only-if-cached header
    bool hasOnlyIfCached() const {return isSet(HttpHdrCcType::CC_ONLY_IF_CACHED);}
    bool onlyIfCached() const {return isSet(HttpHdrCcType::CC_ONLY_IF_CACHED);}
    void onlyIfCached(bool v) {setMask(HttpHdrCcType::CC_ONLY_IF_CACHED,v);}
    void clearOnlyIfCached() {setMask(HttpHdrCcType::CC_ONLY_IF_CACHED,false);}

    //manipulation for Cache-Control: stale-if-error header
    bool hasStaleIfError() const {return isSet(HttpHdrCcType::CC_STALE_IF_ERROR);}
    int32_t staleIfError() const { return stale_if_error;}
    void staleIfError(int32_t v) {setValue(stale_if_error,v,HttpHdrCcType::CC_STALE_IF_ERROR); }
    void clearStaleIfError() {setValue(stale_if_error,STALE_IF_ERROR_UNKNOWN,HttpHdrCcType::CC_STALE_IF_ERROR,false);}

    //manipulation for Cache-Control: immutable header
    bool Immutable() const {return isSet(HttpHdrCcType::CC_IMMUTABLE);}
    void Immutable(bool v) {setMask(HttpHdrCcType::CC_IMMUTABLE,v);}
    void clearImmutable() {setMask(HttpHdrCcType::CC_IMMUTABLE,false);}

    /// check whether the attribute value supplied by id is set
    _SQUID_INLINE_ bool isSet(HttpHdrCcType id) const;

    void packInto(Packable * p) const;

    /** bit-mask representing what header values are set among those
     * recognized by squid.
     *
     * managed via EBIT_SET/TEST/CLR
     */
private:
    int32_t mask;
    int32_t max_age;
    int32_t s_maxage;
    int32_t max_stale;
    int32_t stale_if_error;
    int32_t min_fresh;
    String private_; ///< List of headers sent as value for CC:private="...". May be empty/undefined if the value is missing.
    String no_cache; ///< List of headers sent as value for CC:no-cache="...". May be empty/undefined if the value is missing.

    /// low-level part of the public set method, performs no checks
    _SQUID_INLINE_ void setMask(HttpHdrCcType id, bool newval=true);
    _SQUID_INLINE_ void setValue(int32_t &value, int32_t new_value, HttpHdrCcType hdr, bool setting=true);

public:
    /**comma-separated representation of the header values which were
     * received but are not recognized.
     */
    String other;
};

class StatHist;
class StoreEntry;

void httpHdrCcInitModule(void);
void httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist);
void httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

std::ostream&
operator<< (std::ostream &, HttpHdrCcType);

#if _USE_INLINE_
#include "HttpHdrCc.cci"
#endif

#endif /* SQUID_HTTPHDRCC_H */

