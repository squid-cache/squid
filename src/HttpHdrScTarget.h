/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPHDRSURROGATECONTROLTARGET_H
#define SQUID_HTTPHDRSURROGATECONTROLTARGET_H

#include "defines.h" //for bit mask operations
#include "HttpHdrSc.h"

class Packable;
class StatHist;
class StoreEntry;

/** Representation of HTTP Surogate-Control header field targeted directive
 *
 * \see HttpHdrSc
 */
class HttpHdrScTarget
{
    MEMPROXY_CLASS(HttpHdrScTarget);

    // parsing is done in HttpHdrSc, need to grant them access.
    friend class HttpHdrSc;
public:
    static const int MAX_AGE_UNSET=-1; //max-age is unset
    static const int MAX_STALE_UNSET=0; //max-stale is unset

    HttpHdrScTarget(const char *target_):
        mask(0), max_age(MAX_AGE_UNSET), max_stale(MAX_STALE_UNSET),target(target_) {}
    HttpHdrScTarget(const String &target_):
        mask(0), max_age(MAX_AGE_UNSET), max_stale(MAX_STALE_UNSET),target(target_) {}
    HttpHdrScTarget(const HttpHdrScTarget &t):
        mask(t.mask), max_age(t.max_age), max_stale(t.max_stale),
        content_(t.content_), target(t.target) {}

    bool hasNoStore() const {return isSet(SC_NO_STORE); }
    void noStore(bool v) { setMask(SC_NO_STORE,v); }
    bool noStore() const { return isSet(SC_NO_STORE); }
    void clearNoStore() { setMask(SC_NO_STORE, false); }

    bool hasNoStoreRemote() const {return isSet(SC_NO_STORE_REMOTE); }
    void noStoreRemote(bool v) { setMask(SC_NO_STORE_REMOTE,v); }
    bool noStoreRemote() const { return isSet(SC_NO_STORE_REMOTE); }
    void clearNoStoreRemote() { setMask(SC_NO_STORE_REMOTE, false); }

    bool hasMaxAge() const { return isSet(SC_MAX_AGE); }
    void maxAge(int v) {
        if (v >= 0) { //setting
            setMask(SC_MAX_AGE,true);
            max_age=v;
        } else {
            setMask(SC_MAX_AGE,false);
            max_age=MAX_AGE_UNSET;
        }
    }
    int maxAge() const { return max_age; }
    void clearMaxAge() { setMask(SC_MAX_AGE,false); max_age=MAX_AGE_UNSET; }

    //max_stale has no associated status-bit
    bool hasMaxStale() const { return max_stale != MAX_STALE_UNSET; }
    void maxStale(int v) { max_stale=v; }
    int maxStale() const { return max_stale; }
    void clearMaxStale() { max_stale=MAX_STALE_UNSET; }

    bool hasContent() const { return isSet(SC_CONTENT); }
    void Content(const String &v) {
        setMask(SC_CONTENT,true);
        content_=v;
    }
    String content() const { return content_; }
    void clearContent() { setMask(SC_CONTENT,false); content_.clean(); }

    bool hasTarget() const { return target.size() != 0; }
    String Target() const { return target; }

    void mergeWith(const HttpHdrScTarget * new_sc);
    void packInto(Packable *p) const;
    void updateStats(StatHist *) const;

private:
    bool isSet(http_hdr_sc_type id) const {
        assert (id >= SC_NO_STORE && id < SC_ENUM_END);
        return EBIT_TEST(mask,id);
    }

    void setMask(http_hdr_sc_type id, bool newval) {
        if (newval) EBIT_SET(mask,id);
        else EBIT_CLR(mask,id);
    }

    int mask;
    int max_age;
    int max_stale;
    String content_;
    String target;
    dlink_node node;
};

void httpHdrScTargetStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

#endif /* SQUID_HTTPHDRSURROGATECONTROLTARGET_H */

