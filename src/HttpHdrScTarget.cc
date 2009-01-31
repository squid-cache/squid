
/*
 * $Id$
 *
 * DEBUG: section 90    HTTP Cache Control Header
 * AUTHOR: Alex Rousskov
 *         Robert Collins (Surrogate-Control is derived from
 *         		   Cache-Control).
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
 *
 */

#include "squid.h"
#include "HttpHdrSc.h"

/* local prototypes */

/* module initialization */

/* implementation */

HttpHdrScTarget *
httpHdrScTargetCreate(char const *target)
{
    HttpHdrScTarget *sc = new HttpHdrScTarget();
    sc->max_age = -1;
    /* max_stale is specified as 0 if not specified in the header */
    sc->target = target;
    return sc;
}

void
httpHdrScTargetDestroy(HttpHdrScTarget * sc)
{
    assert(sc);
    sc->target.clean();
    sc->content.clean();
    delete sc;
}

HttpHdrScTarget *
httpHdrScTargetDup(const HttpHdrScTarget * sc)
{
    HttpHdrScTarget *dup;
    assert(sc);
    dup = httpHdrScTargetCreate(sc->target.termedBuf());
    dup->mask = sc->mask;
    dup->max_age = sc->max_age;
    dup->content = sc->content;
    return dup;
}

/* union of two targets */
void
httpHdrScTargetJoinWith(HttpHdrScTarget * sc, const HttpHdrScTarget * new_sc)
{
    assert(sc && new_sc);
    /* TODO: check both targets are the same */

    if (sc->max_age < 0)
        sc->max_age = new_sc->max_age;

    if (sc->max_stale < new_sc->max_stale)
        sc->max_stale = new_sc->max_stale;

    /* RC TODO: copy unique missing content stringlist entries */
    sc->mask |= new_sc->mask;
}

extern http_hdr_sc_type &operator++ (http_hdr_sc_type &aHeader);
extern int operator - (http_hdr_sc_type const &anSc, http_hdr_sc_type const &anSc2);
/* copies non-extant fields from new_sc to this sc */
void
httpHdrScTargetMergeWith(HttpHdrScTarget * sc, const HttpHdrScTarget * new_sc)
{
    http_hdr_sc_type c;
    assert(sc && new_sc);
    /* Don't touch the target - this is used to get the operations for a
     * single surrogate
     */

    for (c = SC_NO_STORE; c < SC_ENUM_END; ++c)
        if (!EBIT_TEST(sc->mask, c) && EBIT_TEST(new_sc->mask,c)) {
            EBIT_SET(sc->mask, c);

            switch (c) {

            case SC_MAX_AGE:
                sc->max_age = new_sc->max_age;
                sc->max_stale = new_sc->max_stale;
                break;

            case SC_CONTENT:
                assert (sc->content.size() == 0);
                sc->content = new_sc->content;
                break;

            default:
                break;
            }
        }
}

/* negative max_age will clean old max_Age setting */
void
httpHdrScTargetSetMaxAge(HttpHdrScTarget * sc, int max_age)
{
    assert(sc);
    sc->max_age = max_age;

    if (max_age >= 0)
        EBIT_SET(sc->mask, SC_MAX_AGE);
    else
        EBIT_CLR(sc->mask, SC_MAX_AGE);
}

void
httpHdrScTargetUpdateStats(const HttpHdrScTarget * sc, StatHist * hist)
{
    http_hdr_sc_type c;
    assert(sc);

    for (c = SC_NO_STORE; c < SC_ENUM_END; ++c)
        if (EBIT_TEST(sc->mask, c))
            statHistCount(hist, c);
}
