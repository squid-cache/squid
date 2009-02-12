/*
 * $Id$
 *
 * DEBUG: section 20    Storage Manager Logging Functions
 * AUTHOR: Duane Wessels
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
#include "MemObject.h"
#include "HttpReply.h"
#include "CacheManager.h"
#include "SquidTime.h"

static const char *storeLogTags[] = {
    "CREATE",
    "SWAPIN",
    "SWAPOUT",
    "RELEASE",
    "SO_FAIL",
};

static int storeLogTagsCounts[STORE_LOG_SWAPOUTFAIL+1];
static OBJH storeLogTagsHist;

static Logfile *storelog = NULL;

static String str_unknown;

void
storeLog(int tag, const StoreEntry * e)
{
    MemObject *mem = e->mem_obj;
    HttpReply const *reply;

    if (str_unknown.undefined())
        str_unknown="unknown"; //hack. Delay initialization as string doesn't support global variables..

    if (NULL == storelog)
        return;

    storeLogTagsCounts[tag]++;
    if (mem != NULL) {
        if (mem->log_url == NULL) {
            debugs(20, 1, "storeLog: NULL log_url for " << mem->url);
            mem->dump();
            mem->log_url = xstrdup(mem->url);
        }

        reply = e->getReply();
        /*
         * XXX Ok, where should we print the dir number here?
         * Because if we print it before the swap file number, it'll break
         * the existing log format.
         */

        String ctype=(reply->content_type.size() ? reply->content_type.termedBuf() : str_unknown);

        logfilePrintf(storelog, "%9d.%03d %-7s %02d %08X %s %4d %9d %9d %9d " SQUIDSTRINGPH " %"PRId64"/%"PRId64" %s %s\n",
                      (int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      storeLogTags[tag],
                      e->swap_dirn,
                      e->swap_filen,
                      e->getMD5Text(),
                      reply->sline.status,
                      (int) reply->date,
                      (int) reply->last_modified,
                      (int) reply->expires,
                      SQUIDSTRINGPRINT(ctype),
                      reply->content_length,
                      e->contentLen(),
                      RequestMethodStr(mem->method),
                      mem->log_url);
    } else {
        /* no mem object. Most RELEASE cases */
        logfilePrintf(storelog, "%9d.%03d %-7s %02d %08X %s   ?         ?         ?         ? ?/? ?/? ? ?\n",
                      (int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      storeLogTags[tag],
                      e->swap_dirn,
                      e->swap_filen,
                      e->getMD5Text());
    }
}

void
storeLogRotate(void)
{
    if (NULL == storelog)
        return;

    logfileRotate(storelog);
}

void
storeLogClose(void)
{
    if (NULL == storelog)
        return;

    logfileClose(storelog);

    storelog = NULL;
}

static void
storeLogRegisterWithCacheManager(void)
{
    CacheManager::GetInstance()->
    registerAction("store_log_tags", "Histogram of store.log tags",
                   storeLogTagsHist, 0, 1);
}

void
storeLogOpen(void)
{
    storeLogRegisterWithCacheManager();

    if (Config.Log.store == NULL || strcmp(Config.Log.store, "none") == 0) {
        debugs(20, 1, "Store logging disabled");
        return;
    }

    storelog = logfileOpen(Config.Log.store, 0, 1);
}

void
storeLogTagsHist(StoreEntry *e)
{
    int tag;
    for (tag = 0; tag <= STORE_LOG_SWAPOUTFAIL; tag++) {
        storeAppendPrintf(e, "%s %d\n",
                          storeLogTags[tag],
                          storeLogTagsCounts[tag]);
    }
}
