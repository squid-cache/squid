
/*
 * $Id: cache_manager.cc,v 1.48 2007/10/31 04:52:16 amosjeffries Exp $
 *
 * DEBUG: section 16    Cache Manager Objects
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

#include "CacheManager.h"
#include "errorpage.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "Store.h"
#include "fde.h"
#include "SquidTime.h"
#include "wordlist.h"

#define MGR_PASSWD_SZ 128

typedef struct
{
    StoreEntry *entry;
    char *action;
    char *user_name;
    char *passwd;
}

cachemgrStateData;


static CacheManagerAction *cachemgrFindAction(const char *action);
static cachemgrStateData *cachemgrParseUrl(const char *url);
static void cachemgrParseHeaders(cachemgrStateData * mgr, const HttpRequest * request);
static int cachemgrCheckPassword(cachemgrStateData *);
static void cachemgrStateFree(cachemgrStateData * mgr);
static char *cachemgrPasswdGet(cachemgr_passwd *, const char *);
static const char *cachemgrActionProtection(const CacheManagerAction * at);
static OBJH cachemgrShutdown;
static OBJH cachemgrReconfigure;
static OBJH cachemgrMenu;
static OBJH cachemgrOfflineToggle;

CacheManagerAction *ActionTable = NULL;

CacheManager::CacheManager()
{
    registerAction("menu", "This Cachemanager Menu", cachemgrMenu, 0, 1);
    registerAction("shutdown",
                   "Shut Down the Squid Process",
                   cachemgrShutdown, 1, 1);
    registerAction("reconfigure",
                     "Reconfigure the Squid Process",
                     cachemgrReconfigure, 1, 1);
    registerAction("offline_toggle",
                   "Toggle offline_mode setting",
                   cachemgrOfflineToggle, 1, 1);
}

void
CacheManager::registerAction(char const * action, char const * desc, OBJH * handler, int pw_req_flag, int atomic)
{
    CacheManagerAction *a;
    CacheManagerAction **A;

    if (findAction(action) != NULL) {
        debugs(16, 3, "CacheManager::registerAction: Duplicate '" << action << "'");
        return;
    }

    assert (strstr (" ", action) == NULL);
    a = (CacheManagerAction *)xcalloc(1, sizeof(CacheManagerAction));
    a->action = xstrdup(action);
    a->desc = xstrdup(desc);
    a->handler = handler;
    a->flags.pw_req = pw_req_flag;
    a->flags.atomic = atomic;

    for (A = &ActionTable; *A; A = &(*A)->next)

        ;
    *A = a;

    debugs(16, 3, "CacheManager::registerAction: registered " <<  action);
}

CacheManagerAction *
CacheManager::findAction(char const * action)
{
    return cachemgrFindAction(action);
}

static CacheManagerAction *
cachemgrFindAction(const char *action)
{
    CacheManagerAction *a;

    for (a = ActionTable; a != NULL; a = a->next) {
        if (0 == strcmp(a->action, action))
            return a;
    }

    return NULL;
}

static cachemgrStateData *
cachemgrParseUrl(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    CacheManagerAction *a;
    cachemgrStateData *mgr = NULL;
    const char *prot;
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);

    if (t < 2) {
        xstrncpy(request, "menu", MAX_URL);
#ifdef _SQUID_OS2_
        /*
         * emx's sscanf insists of returning 2 because it sets request
         * to null
         */
    } else if (request[0] == '\0') {
        xstrncpy(request, "menu", MAX_URL);
#endif

    } else if ((a = cachemgrFindAction(request)) == NULL) {
        debugs(16, 1, "cachemgrParseUrl: action '" << request << "' not found");
        return NULL;
    } else {
        prot = cachemgrActionProtection(a);

        if (!strcmp(prot, "disabled") || !strcmp(prot, "hidden")) {
            debugs(16, 1, "cachemgrParseUrl: action '" << request << "' is " << prot);
            return NULL;
        }
    }

    /* set absent entries to NULL so we can test if they are present later */
    mgr = (cachemgrStateData *)xcalloc(1, sizeof(cachemgrStateData));

    mgr->user_name = NULL;

    mgr->passwd = t == 3 ? xstrdup(password) : NULL;

    mgr->action = xstrdup(request);

    return mgr;
}

static void
cachemgrParseHeaders(cachemgrStateData * mgr, const HttpRequest * request)
{
    const char *basic_cookie;	/* base 64 _decoded_ user:passwd pair */
    const char *passwd_del;
    assert(mgr && request);
    basic_cookie = request->header.getAuth(HDR_AUTHORIZATION, "Basic");

    if (!basic_cookie)
        return;

    if (!(passwd_del = strchr(basic_cookie, ':'))) {
        debugs(16, 1, "cachemgrParseHeaders: unknown basic_cookie format '" << basic_cookie << "'");
        return;
    }

    /* found user:password pair, reset old values */
    safe_free(mgr->user_name);

    safe_free(mgr->passwd);

    mgr->user_name = xstrdup(basic_cookie);

    mgr->user_name[passwd_del - basic_cookie] = '\0';

    mgr->passwd = xstrdup(passwd_del + 1);

    /* warning: this prints decoded password which maybe not what you want to do @?@ @?@ */
    debugs(16, 9, "cachemgrParseHeaders: got user: '" << mgr->user_name << "' passwd: '" << mgr->passwd << "'");
}

/*
 * return 0 if mgr->password is good
 */
static int
cachemgrCheckPassword(cachemgrStateData * mgr)
{
    char *pwd = cachemgrPasswdGet(Config.passwd_list, mgr->action);
    CacheManagerAction *a = cachemgrFindAction(mgr->action);
    assert(a != NULL);

    if (pwd == NULL)
        return a->flags.pw_req;

    if (strcmp(pwd, "disable") == 0)
        return 1;

    if (strcmp(pwd, "none") == 0)
        return 0;

    if (!mgr->passwd)
        return 1;

    return strcmp(pwd, mgr->passwd);
}

static void
cachemgrStateFree(cachemgrStateData * mgr)
{
    safe_free(mgr->action);
    safe_free(mgr->user_name);
    safe_free(mgr->passwd);
    mgr->entry->unlock();
    xfree(mgr);
}

void
cachemgrStart(int fd, HttpRequest * request, StoreEntry * entry)
{
    cachemgrStateData *mgr = NULL;
    ErrorState *err = NULL;
    CacheManagerAction *a;
    debugs(16, 3, "objectcacheStart: '" << entry->url() << "'" );

    if ((mgr = cachemgrParseUrl(entry->url())) == NULL) {
        err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND, request);
        err->url = xstrdup(entry->url());
        errorAppendEntry(entry, err);
        entry->expires = squid_curtime;
        return;
    }

    mgr->entry = entry;

    entry->lock()

    ;
    entry->expires = squid_curtime;

    debugs(16, 5, "CACHEMGR: " << fd_table[fd].ipaddr << " requesting '" << mgr->action << "'");

    /* get additional info from request headers */
    cachemgrParseHeaders(mgr, request);

    /* Check password */

    if (cachemgrCheckPassword(mgr) != 0) {
        /* build error message */
        ErrorState *err;
        HttpReply *rep;
        err = errorCon(ERR_CACHE_MGR_ACCESS_DENIED, HTTP_UNAUTHORIZED, request);
        /* warn if user specified incorrect password */

        if (mgr->passwd)
            debugs(16, 1, "CACHEMGR: " << 
                   (mgr->user_name ? mgr->user_name : "<unknown>") << "@" << 
                   fd_table[fd].ipaddr << ": incorrect password for '" << 
                   mgr->action << "'" );
        else
            debugs(16, 1, "CACHEMGR: " << 
                   (mgr->user_name ? mgr->user_name : "<unknown>") << "@" << 
                   fd_table[fd].ipaddr << ": password needed for '" << 
                   mgr->action << "'" );

        rep = errorBuildReply(err);

        errorStateFree(err);

        /*
         * add Authenticate header, use 'action' as a realm because
         * password depends on action
         */
        rep->header.putAuth("Basic", mgr->action);

        /* store the reply */
        entry->replaceHttpReply(rep);

        entry->expires = squid_curtime;

        entry->complete();

        cachemgrStateFree(mgr);

        return;
    }

    debugs(16, 1, "CACHEMGR: " << 
           (mgr->user_name ? mgr->user_name : "<unknown>") << "@" << 
           fd_table[fd].ipaddr << " requesting '" << 
           mgr->action << "'" );
    /* retrieve object requested */
    a = cachemgrFindAction(mgr->action);
    assert(a != NULL);

    entry->buffer();

    {
        HttpVersion version(1,0);
        HttpReply *rep = new HttpReply;
        rep->setHeaders(version,
                        HTTP_OK,
                        NULL,
                        "text/plain",
                        -1,			/* C-Len */
                        squid_curtime,	/* LMT */
                        squid_curtime);
        entry->replaceHttpReply(rep);
    }

    a->handler(entry);

    entry->flush();

    if (a->flags.atomic)
        entry->complete();

    cachemgrStateFree(mgr);
}

static void
cachemgrShutdown(StoreEntry * entryunused)
{
    debugs(16, 0, "Shutdown by command.");
    shut_down(0);
}

static void
cachemgrReconfigure(StoreEntry * sentry)
{
    debug(16, 0) ("Reconfigure by command.\n");
    storeAppendPrintf(sentry, "Reconfiguring Squid Process ....");
    reconfigure(SIGHUP);
}

/// \ingroup CacheManagerInternal
static void
cachemgrOfflineToggle(StoreEntry * sentry)
{
    Config.onoff.offline = !Config.onoff.offline;
    debugs(16, 0, "offline_mode now " << (Config.onoff.offline ? "ON" : "OFF") << ".");

    storeAppendPrintf(sentry, "offline_mode is now %s\n",
                      Config.onoff.offline ? "ON" : "OFF");
}

static const char *
cachemgrActionProtection(const CacheManagerAction * at)
{
    char *pwd;
    assert(at);
    pwd = cachemgrPasswdGet(Config.passwd_list, at->action);

    if (!pwd)
        return at->flags.pw_req ? "hidden" : "public";

    if (!strcmp(pwd, "disable"))
        return "disabled";

    if (strcmp(pwd, "none") == 0)
        return "public";

    return "protected";
}

static void
cachemgrMenu(StoreEntry * sentry)
{
    CacheManagerAction *a;

    for (a = ActionTable; a != NULL; a = a->next) {
        storeAppendPrintf(sentry, " %-22s\t%-32s\t%s\n",
                          a->action, a->desc, cachemgrActionProtection(a));
    }
}

static char *
cachemgrPasswdGet(cachemgr_passwd * a, const char *action)
{
    wordlist *w;

    while (a != NULL) {
        for (w = a->actions; w != NULL; w = w->next) {
            if (0 == strcmp(w->key, action))
                return a->passwd;

            if (0 == strcmp(w->key, "all"))
                return a->passwd;
        }

        a = a->next;
    }

    return NULL;
}
