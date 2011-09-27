/*
 * HttpHdrCc.h
 *
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 */

#ifndef SQUID_HTTPHDRCC_H
#define SQUID_HTTPHDRCC_H

#include "config.h"
#include "MemPool.h"
#include "SquidString.h"

/** Http Cache-Control header representation
 *
 * Store and parse the Cache-Control HTTP header.
 */
class HttpHdrCc
{

public:
	static const int32_t MAX_AGE_UNSET=-1; //max-age is unset
	static const int32_t S_MAXAGE_UNSET=-1; //s-maxage is unset
	static const int32_t MAX_STALE_UNSET=-1; //max-stale is unset
	static const int32_t MAX_STALE_ALWAYS=-2; //max-stale is set to no value
	static const int32_t STALE_IF_ERROR_UNSET=-1; //stale_if_error is unset
	static const int32_t MIN_FRESH_UNSET=-1; //min_fresh is unset

    HttpHdrCc() :
            mask(0), max_age(MAX_AGE_UNSET), s_maxage(S_MAXAGE_UNSET),
            max_stale(MAX_STALE_UNSET), stale_if_error(STALE_IF_ERROR_UNSET),
            min_fresh(MIN_FRESH_UNSET) {}

    /// reset data-members to default state
    void clear();

    /// parse a header-string and fill in appropriate values.
    bool parse(const String & s);

    /// max-age setter. Clear by setting to MAX_AGE_UNSET
    _SQUID_INLINE_ void setMaxAge(int32_t max_age);
    _SQUID_INLINE_ int32_t getMaxAge() const;

    /// s-maxage setter. Clear by setting to S_MAXAGE_UNSET
    _SQUID_INLINE_ void setSMaxAge(int32_t s_maxage);
    _SQUID_INLINE_ int32_t getSMaxAge() const;

    /// max-stale setter. Clear by setting to MAX_STALE_UNSET
    _SQUID_INLINE_ void setMaxStale(int32_t max_stale);
    _SQUID_INLINE_ int32_t getMaxStale() const;

    /// stale-if-error setter. Clear by setting to STALE_IF_ERROR_UNSET
    _SQUID_INLINE_ void setStaleIfError(int32_t stale_if_error);
    _SQUID_INLINE_ int32_t getStaleIfError() const;

    /// min-fresh setter. Clear by setting to MIN_FRESH_UNSET
    _SQUID_INLINE_ void setMinFresh(int32_t min_fresh);
    _SQUID_INLINE_ int32_t getMinFresh() const;

    MEMPROXY_CLASS(HttpHdrCc);

    /** bit-mask representing what header values are set among those
     * recognized by squid.
     *
     * managed via EBIT_SET/TEST/CLR
     */
    int32_t mask;
private:
    int32_t max_age;
    int32_t s_maxage;
    int32_t max_stale;
    int32_t stale_if_error;
    int32_t min_fresh;
public:
    /**comma-separated representation of the header values which were
     * received but are not recognized.
     */
    String other;
};

MEMPROXY_CLASS_INLINE(HttpHdrCc);

#if _USE_INLINE_
#include "HttpHdrCc.cci"
#endif

#endif /* SQUID_HTTPHDRCC_H */
