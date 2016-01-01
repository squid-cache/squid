/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 90    HTTP Cache Control Header */

#include "squid.h"
#include "HttpHdrSc.h"
#include "HttpHeader.h"
#include "HttpHeaderFieldInfo.h"
#include "HttpHeaderFieldStat.h"
#include "HttpHeaderStat.h"
#include "HttpHeaderTools.h"
#include "Store.h"
#include "StrList.h"

#include <map>

/* a row in the table used for parsing surrogate-control header and statistics */
typedef struct {
    const char *name;
    http_hdr_sc_type id;
    HttpHeaderFieldStat stat;
} HttpHeaderScFields;

/* this table is used for parsing surrogate control header */
/* order must match that of enum http_hdr_sc_type. The constraint is verified at initialization time */
//todo: implement constraint
static const HttpHeaderFieldAttrs ScAttrs[SC_ENUM_END] = {
    {"no-store", (http_hdr_type)SC_NO_STORE},
    {"no-store-remote", (http_hdr_type)SC_NO_STORE_REMOTE},
    {"max-age", (http_hdr_type)SC_MAX_AGE},
    {"content", (http_hdr_type)SC_CONTENT},
    {"Other,", (http_hdr_type)SC_OTHER} /* ',' will protect from matches */
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

/* creates an sc object from a 0-terminating string */
HttpHdrSc *
httpHdrScParseCreate(const String & str)
{
    HttpHdrSc *sc = new HttpHdrSc();

    if (!sc->parse(&str)) {
        delete sc;
        sc = NULL;
    }

    return sc;
}

/* parses a 0-terminating string and inits sc */
bool
HttpHdrSc::parse(const String * str)
{
    HttpHdrSc * sc=this;
    const char *item;
    const char *p;      /* '=' parameter */
    const char *pos = NULL;
    const char *target = NULL; /* ;foo */
    const char *temp = NULL; /* temp buffer */
    int type;
    int ilen, vlen;
    int initiallen;
    HttpHdrScTarget *sct;
    assert(str);

    /* iterate through comma separated list */

    while (strListGetItem(str, ',', &item, &ilen, &pos)) {
        initiallen = ilen;
        vlen = 0;
        /* decrease ilen to still match the token for  '=' statements */

        if ((p = strchr(item, '=')) && (p - item < ilen)) {
            vlen = ilen - (p + 1 - item);
            ilen = p - item;
            ++p;
        }

        /* decrease ilen to still match the token for ';' qualified non '=' statments */
        else if ((p = strchr(item, ';')) && (p - item < ilen)) {
            ilen = p - item;
            ++p;
        }

        /* find type */
        /* TODO: use a type-safe map-based lookup */
        type = httpHeaderIdByName(item, ilen,
                                  ScFieldsInfo, SC_ENUM_END);

        if (type < 0) {
            debugs(90, 2, "hdr sc: unknown control-directive: near '" << item << "' in '" << str << "'");
            type = SC_OTHER;
        }

        /* Is this a targeted directive? */
        /* TODO: remove the temporary useage and use memrchr and the information we have instead */
        temp = xstrndup (item, initiallen + 1);

        if (!((target = strrchr (temp, ';')) && !strchr (target, '"') && *(target + 1) != '\0'))
            target = NULL;
        else
            ++target;

        sct = sc->findTarget(target);

        if (!sct) {
            sct = new HttpHdrScTarget(target);
            addTarget(sct);
        }

        safe_free (temp);

        if (sct->isSet(static_cast<http_hdr_sc_type>(type))) {
            if (type != SC_OTHER)
                debugs(90, 2, "hdr sc: ignoring duplicate control-directive: near '" << item << "' in '" << str << "'");

            ++ ScFieldsInfo[type].stat.repCount;

            continue;
        }

        /* process directives */
        switch (type) {
        case SC_NO_STORE:
            sct->noStore(true);
            break;

        case SC_NO_STORE_REMOTE:
            sct->noStoreRemote(true);
            break;

        case SC_MAX_AGE: {
            int ma;
            if (p && httpHeaderParseInt(p, &ma)) {
                sct->maxAge(ma);

                if ((p = strchr (p, '+'))) {
                    int ms;
                    ++p; //skip the + char
                    if (httpHeaderParseInt(p, &ms)) {
                        sct->maxStale(ms);
                    } else {
                        debugs(90, 2, "sc: invalid max-stale specs near '" << item << "'");
                        sct->clearMaxStale();
                        /* leave the max-age alone */
                    }
                }
            } else {
                debugs(90, 2, "sc: invalid max-age specs near '" << item << "'");
                sct->clearMaxAge();
            }

            break;
        }

        case SC_CONTENT:

            if ( p && httpHeaderParseQuotedString(p, vlen, &sct->content_)) {
                sct->setMask(SC_CONTENT,true); // ugly but saves a copy
            } else {
                debugs(90, 2, "sc: invalid content= quoted string near '" << item << "'");
                sct->clearContent();
            }
            break;

        case SC_OTHER:
        default:
            break;
        }
    }

    return sc->targets.head != NULL;
}

HttpHdrSc::~HttpHdrSc()
{
    if (targets.head) {
        dlink_node *sct = targets.head;

        while (sct) {
            HttpHdrScTarget *t = static_cast<HttpHdrScTarget *>(sct->data);
            sct = sct->next;
            dlinkDelete (&t->node, &targets);
            delete t;
        }
    }
}

HttpHdrSc::HttpHdrSc(const HttpHdrSc &sc)
{
    dlink_node *node = sc.targets.head;

    while (node) {
        HttpHdrScTarget *dupsct = new HttpHdrScTarget(*static_cast<HttpHdrScTarget *>(node->data));
        addTargetAtTail(dupsct);
        node = node->next;
    }
}

void
HttpHdrScTarget::packInto(Packer * p) const
{
    http_hdr_sc_type flag;
    int pcount = 0;
    assert (p);

    for (flag = SC_NO_STORE; flag < SC_ENUM_END; ++flag) {
        if (isSet(flag) && flag != SC_OTHER) {

            /* print option name */
            packerPrintf(p, (pcount ? ", " SQUIDSTRINGPH : SQUIDSTRINGPH),
                         SQUIDSTRINGPRINT(ScFieldsInfo[flag].name));

            /* handle options with values */

            if (flag == SC_MAX_AGE)
                packerPrintf(p, "=%d", (int) max_age);

            if (flag == SC_CONTENT)
                packerPrintf(p, "=\"" SQUIDSTRINGPH "\"", SQUIDSTRINGPRINT(content_));

            ++pcount;
        }
    }

    if (hasTarget())
        packerPrintf (p, ";" SQUIDSTRINGPH, SQUIDSTRINGPRINT(target));
}

void
HttpHdrSc::packInto(Packer * p) const
{
    dlink_node *node;
    assert(p);
    node = targets.head;

    while (node) {
        static_cast<HttpHdrScTarget *>(node->data)->packInto(p);
        node = node->next;
    }
}

/* negative max_age will clean old max_Age setting */
void
HttpHdrSc::setMaxAge(char const *target, int max_age)
{
    HttpHdrScTarget *sct = findTarget(target);

    if (!sct) {
        sct = new HttpHdrScTarget(target);
        dlinkAddTail (sct, &sct->node, &targets);
    }

    sct->maxAge(max_age);
}

void
HttpHdrSc::updateStats(StatHist * hist) const
{
    dlink_node *sct = targets.head;

    while (sct) {
        static_cast<HttpHdrScTarget *>(sct->data)->updateStats(hist);
        sct = sct->next;
    }
}

void
httpHdrScTargetStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat;     /* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < SC_ENUM_END;
    const char *name = valid_id ? ScFieldsInfo[id].name.termedBuf() : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->scParsedCount));
}

void
httpHdrScStatDumper(StoreEntry * sentry, int idx, double val, double size, int count)
{
    extern const HttpHeaderStat *dump_stat; /* argh! */
    const int id = (int) val;
    const int valid_id = id >= 0 && id < SC_ENUM_END;
    const char *name = valid_id ? ScFieldsInfo[id].name.termedBuf() : "INVALID";

    if (count || valid_id)
        storeAppendPrintf(sentry, "%2d\t %-20s\t %5d\t %6.2f\n",
                          id, name, count, xdiv(count, dump_stat->scParsedCount));
}

HttpHdrScTarget *
HttpHdrSc::findTarget(const char *target)
{
    dlink_node *node;
    node = targets.head;

    while (node) {
        HttpHdrScTarget *sct = (HttpHdrScTarget *)node->data;

        if (target && sct->target.size() > 0 && !strcmp(target, sct->target.termedBuf()))
            return sct;
        else if (!target && sct->target.size() == 0)
            return sct;

        node = node->next;
    }

    return NULL;
}

HttpHdrScTarget *
HttpHdrSc::getMergedTarget(const char *ourtarget)
{
    HttpHdrScTarget *sctus = findTarget(ourtarget);
    HttpHdrScTarget *sctgeneric = findTarget(NULL);

    if (sctgeneric || sctus) {
        HttpHdrScTarget *sctusable = new HttpHdrScTarget(NULL);

        if (sctgeneric)
            sctusable->mergeWith(sctgeneric);

        if (sctus)
            sctusable->mergeWith(sctus);

        return sctusable;
    }

    return NULL;
}

