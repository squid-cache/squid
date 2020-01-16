/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 20    Storage Manager Logging Functions */

#include "squid.h"
#include "format/Token.h"
#include "HttpReply.h"
#include "log/File.h"
#include "MemObject.h"
#include "mgr/Registration.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"
#include "store_log.h"

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

    if (str_unknown.size()==0)
        str_unknown="unknown"; //hack. Delay initialization as string doesn't support global variables..

    if (NULL == storelog)
        return;

    ++storeLogTagsCounts[tag];
    if (mem != NULL) {
        reply = e->getReply();
        /*
         * XXX Ok, where should we print the dir number here?
         * Because if we print it before the swap file number, it'll break
         * the existing log format.
         */

        String ctype=(reply->content_type.size() ? reply->content_type.termedBuf() : str_unknown);

        // mem_obj may still lack logging details; especially in RELEASE cases
        const char *logUri = mem->hasUris() ? mem->logUri() : "?";

        logfileLineStart(storelog);
        logfilePrintf(storelog, "%9d.%03d %-7s %02d %08X %s %4d %9d %9d %9d " SQUIDSTRINGPH " %" PRId64 "/%" PRId64 " " SQUIDSBUFPH " %s\n",
                      (int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      storeLogTags[tag],
                      e->swap_dirn,
                      e->swap_filen,
                      e->getMD5Text(),
                      reply->sline.status(),
                      (int) reply->date,
                      (int) reply->last_modified,
                      (int) reply->expires,
                      SQUIDSTRINGPRINT(ctype),
                      reply->content_length,
                      e->contentLen(),
                      SQUIDSBUFPRINT(mem->method.image()),
                      logUri);
        logfileLineEnd(storelog);
    } else {
        /* no mem object. Most RELEASE cases */
        logfileLineStart(storelog);
        logfilePrintf(storelog, "%9d.%03d %-7s %02d %08X %s   ?         ?         ?         ? ?/? ?/? ? ?\n",
                      (int) current_time.tv_sec,
                      (int) current_time.tv_usec / 1000,
                      storeLogTags[tag],
                      e->swap_dirn,
                      e->swap_filen,
                      e->getMD5Text());
        logfileLineEnd(storelog);
    }
}

void
storeLogRotate(void)
{
    if (NULL == storelog)
        return;

    logfileRotate(storelog, Config.Log.rotateNumber);
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
    Mgr::RegisterAction("store_log_tags", "Histogram of store.log tags",
                        storeLogTagsHist, 0, 1);
}

void
storeLogOpen(void)
{
    storeLogRegisterWithCacheManager();

    if (Config.Log.store == NULL || strcmp(Config.Log.store, "none") == 0) {
        debugs(20, DBG_IMPORTANT, "Store logging disabled");
        return;
    }

    storelog = logfileOpen(Config.Log.store, 0, 1);
}

void
storeLogTagsHist(StoreEntry *e)
{
    int tag;
    for (tag = 0; tag <= STORE_LOG_SWAPOUTFAIL; ++tag) {
        storeAppendPrintf(e, "%s %d\n",
                          storeLogTags[tag],
                          storeLogTagsCounts[tag]);
    }
}

