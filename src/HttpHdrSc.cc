
/*
 * $Id: HttpHdrSc.cc,v 1.3 2006/04/22 05:29:17 robertc Exp $
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
#include "Store.h"
#include "HttpHeader.h"
#include "HttpHdrSc.h"

/* this table is used for parsing surrogate control header */
static const HttpHeaderFieldAttrs ScAttrs[SC_ENUM_END] =
    {
        {"no-store", (http_hdr_type)SC_NO_STORE},

        {"no-store-remote", (http_hdr_type)SC_NO_STORE_REMOTE},
        {"max-age", (http_hdr_type)SC_MAX_AGE},
        {"content", (http_hdr_type)SC_CONTENT},
        {"Other,", (http_hdr_type)SC_OTHER}	/* ',' will protect from matches */
    };

HttpHeaderFieldInfo *ScFieldsInfo = NULL;

http_hdr_sc_type &operator++ (http_hdr_sc_type &aHeader)
{
    int tmp = (int)aHeader;
    aHeader = (http_hdr_sc_type)(++tmp);
    return aHeader;
}

int operator - (http_hdr_sc_type const &anSc, http_hdr_sc_type const &anSc2)
{
    return (int)anSc - (int)anSc2;
}


/* local prototypes */
static int httpHdrScParseInit(HttpHdrSc * sc, const String * str);

/* module initialization */

void
httpHdrScInitModule(void)
{
    ScFieldsInfo = httpHeaderBuildFieldsInfo(ScAttrs, SC_ENUM_END);
}

void
httpHdrScCleanModule(void)
{
    httpHeaderDestroyFieldsInfo(ScFieldsInfo, SC_ENUM_END);
    ScFieldsInfo = NULL;
}

/* implementation */

HttpHdrSc *
httpHdrScCreate(void)
{
    return new HttpHdrSc();
}

/* creates an sc object from a 0-terminating string */
HttpHdrSc *
httpHdrScParseCreate(const String * str)
{
    HttpHdrSc *sc = httpHdrScCreate();

    if (!httpHdrScParseInit(sc, str)) {
        httpHdrScDestroy(sc);
        sc = NULL;
    }

    return sc;
}

/* parses a 0-terminating string and inits sc */
static int
httpHdrScParseInit(HttpHdrSc * sc, const String * str)
{
    const char *item;
    const char *p;		/* '=' parameter */
    const char *pos = NULL;
    const char *target = NULL; /* ;foo */
    const char *temp = NULL; /* temp buffer */
    int type;
    int ilen;
    int initiallen;
    HttpHdrScTarget *sct;
    assert(sc && str);

    /* iterate through comma separated list */

    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
        initiallen = ilen;
        /* decrease ilen to still match the token for  '=' statements */

        if ((p = strchr(item, '=')) && (p - item < ilen))
            ilen = p++ - item;

        /* decrease ilen to still match the token for ';' qualified non '=' statments */
        else if ((p = strchr(item, ';')) && (p - item < ilen))
            ilen = p++ - item;

        /* find type */
        type = httpHeaderIdByName(item, ilen,
                                  ScFieldsInfo, SC_ENUM_END);

        if (type < 0) {
            debug(90, 2) ("hdr sc: unknown control-directive: near '%s' in '%s'\n", item, str->buf());
            type = SC_OTHER;
        }

        /* Is this a targeted directive? */
        /* TODO sometime: implement a strnrchr that looks at a substring */
        temp = xstrndup (item, initiallen + 1);

        if (!((target = strrchr (temp, ';')) && !strchr (target, '"') && *(target + 1) != '\0'))
            target = NULL;
        else
            ++target;

        sct = httpHdrScFindTarget (sc, target);

        if (!sct) {
            sct = httpHdrScTargetCreate (target);
            dlinkAdd(sct, &sct->node, &sc->targets);
        }

        safe_free (temp);

        if (EBIT_TEST(sct->mask, type)) {
            if (type != SC_OTHER)
                debug(90, 2) ("hdr sc: ignoring duplicate control-directive: near '%s' in '%s'\n", item, str->buf());

            ScFieldsInfo[type].stat.repCount++;

            continue;
        }

        /* update mask */
        EBIT_SET(sct->mask, type);

        /* post-processing special cases */
        switch (type) {

        case SC_MAX_AGE:

            if (!p || !httpHeaderParseInt(p, &sct->max_age)) {
                debug(90, 2) ("sc: invalid max-age specs near '%s'\n", item);
                sct->max_age = -1;
                EBIT_CLR(sct->mask, type);
            }

            if ((p = strchr (p, '+')))
                if (!httpHeaderParseInt(++p, &sct->max_stale)) {
                    debug(90, 2) ("sc: invalid max-stale specs near '%s'\n", item);
                    sct->max_stale = 0;
                    /* leave the max-age alone */
                }

            break;

        case SC_CONTENT:

            if (!p || !httpHeaderParseQuotedString(p, &sct->content)) {
                debug (90, 2) ("sc: invalid content= quoted string near '%s'\n",item);
                sct->content.clean();
                EBIT_CLR(sct->mask, type);
            }

        default:
            break;
        }
    }

    return sc->targets.head != NULL;
}

void
httpHdrScDestroy(HttpHdrSc * sc)
{
    assert(sc);

    if (sc->targets.head) {
        dlink_node *sct = sc->targets.head;

        while (sct) {
            HttpHdrScTarget *t = (HttpHdrScTarget *)sct->data;
            sct = sct->next;
            dlinkDelete (&t->node, &sc->targets);
            httpHdrScTargetDestroy (t);
        }
    }

    delete sc;
}

HttpHdrSc *
httpHdrScDup(const HttpHdrSc * sc)
{
    HttpHdrSc *dup;
    dlink_node *node;
    assert(sc);
    node = sc->targets.head;
    dup = httpHdrScCreate();

    while (node) {
        HttpHdrScTarget *dupsct;
        dupsct = httpHdrScTargetDup ((HttpHdrScTarget *)node->data);
        dlinkAddTail (dupsct, &dupsct->node, &dup->targets);
        node = node->next;
    }

    return dup;
}

void
httpHdrScTargetPackInto(const HttpHdrScTarget * sc, Packer * p)
{
    http_hdr_sc_type flag;
    int pcount = 0;
    assert(sc && p);

    for (flag = SC_NO_STORE; flag < SC_ENUM_END; ++flag) {
        if (EBIT_TEST(sc->mask, flag) && flag != SC_OTHER) {

            /* print option name */
            packerPrintf(p, (pcount ? ", %s" : "%s"), ScFieldsInfo[flag].name.buf());

            /* handle options with values */

            if (flag == SC_MAX_AGE)
                packerPrintf(p, "=%d", (int) sc->max_age);

            if (flag == SC_CONTENT)
                packerPrintf(p, "=\"%s\"", sc->content.buf());

            pcount++;
        }
    }

    if (sc->target.size())
        packerPrintf (p, ";%s", sc->target.buf());
}

void
httpHdrScPackInto(const HttpHdrSc * sc, Packer * p)
{
    dlink_node *node;
    assert(sc && p);
    node = sc->targets.head;

    while (node) {
        httpHdrScTargetPackInto((HttpHdrScTarget *)node->data, p);
        node = node->next;
    }
}

void
httpHdrScJoinWith(HttpHdrSc * sc, const HttpHdrSc * new_sc)
{
    assert(sc && new_sc);
#if 0
    /* RC TODO: check that both have the same target */

    if (sc->max_age < 0)
        sc->max_age = new_sc->max_age;

    /* RC TODO: copy unique missing stringlist entries */
    cc->mask |= new_cc->mask;

#endif
}

/* negative max_age will clean old max_Age setting */
void
httpHdrScSetMaxAge(HttpHdrSc * sc, char const *target, int max_age)
{
    HttpHdrScTarget *sct;
    assert(sc);
    sct = httpHdrScFindTarget (sc, target);

    if (!sct) {
        sct = httpHdrScTargetCreate (target);
        dlinkAddTail (sct, &sct->node, &sc->targets);
    }

    httpHdrScTargetSetMaxAge(sct, max_age);
}

void
httpHdrScUpdateStats(const HttpHdrSc * sc, StatHist * hist)
{
    dlink_node *sct;
    assert(sc);
    sct = sc->targets.head;

    while (sct) {
        httpHdrScTargetUpdateStats((HttpHdrScTarget *)sct->data, hist);
        sct = sct->next;
    }
}

void
httpHdrScTargetStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat;     /* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < SC_ENUM_END;
    const char *name = valid_id ? ScFieldsInfo[id].name.buf() : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->scParsedCount));
}

void
httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat;	/* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < SC_ENUM_END;
    const char *name = valid_id ? ScFieldsInfo[id].name.buf() : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->scParsedCount));
}

HttpHdrScTarget *
httpHdrScFindTarget (HttpHdrSc *sc, const char *target)
{
    dlink_node *node;
    assert (sc);
    node = sc->targets.head;

    while (node) {
        HttpHdrScTarget *sct = (HttpHdrScTarget *)node->data;

        if (target && sct->target.buf() && !strcmp (target, sct->target.buf()))
            return sct;
        else if (!target && !sct->target.buf())
            return sct;

        node = node->next;
    }

    return NULL;
}

HttpHdrScTarget *
httpHdrScGetMergedTarget (HttpHdrSc *sc, const char *ourtarget)
{
    HttpHdrScTarget *sctus = httpHdrScFindTarget (sc, ourtarget);
    HttpHdrScTarget *sctgeneric = httpHdrScFindTarget (sc, NULL);

    if (sctgeneric || sctus) {
        HttpHdrScTarget *sctusable = httpHdrScTargetCreate (NULL);

        if (sctgeneric)
            httpHdrScTargetMergeWith (sctusable, sctgeneric);

        if (sctus)
            httpHdrScTargetMergeWith (sctusable, sctus);

        return sctusable;
    }

    return NULL;
}
