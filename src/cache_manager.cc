
/*
 * $Id: cache_manager.cc,v 1.1 1998/02/19 23:09:48 wessels Exp $
 *
 * DEBUG: section 16    Cache Manager Objects
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * --------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by
 *  the National Science Foundation.
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  
 */

#include "squid.h"

#define MGR_PASSWD_SZ 128

typedef struct {
    StoreEntry *entry;
    char *action;
    char *passwd;
} cachemgrStateData;

typedef struct _action_table {
    char *action;
    char *desc;
    OBJH *handler;
    int pw_req_flag;
    struct _action_table *next;
} action_table;

static action_table * cachemgrFindAction(const char *action);
static cachemgrStateData *cachemgrParse(const char *url);
static int cachemgrCheckPassword(cachemgrStateData *);
static void cachemgrStateFree(cachemgrStateData *mgr);
static char *cachemgrPasswdGet(cachemgr_passwd *, const char *);
static OBJH cachemgrShutdown;
static OBJH cachemgrMenu;

action_table *ActionTable = NULL;

void
cachemgrRegister(const char *action, const char *desc, OBJH * handler, int pw_req_flag)
{
    action_table *a;
    action_table **A;
    assert(cachemgrFindAction(action) == NULL);
    a = xcalloc(1, sizeof(action_table));
    a->action = xstrdup(action);
    a->desc = xstrdup(desc);
    a->handler = handler;
    a->pw_req_flag = pw_req_flag;
    for (A = &ActionTable; *A; A = &(*A)->next);
    *A = a;
    debug(16, 1)("cachemgrRegister: registered %s\n", action);
}

static action_table *
cachemgrFindAction(const char *action)
{
    action_table *a;
    for (a = ActionTable; a != NULL; a = a->next) {
	if (0 == strcmp(a->action, action))
	    return a;
    }
    return NULL;
}

static cachemgrStateData *
cachemgrParse(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    action_table *a;
    cachemgrStateData *mgr = NULL;
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);
    if (t < 2) {
	xstrncpy(request, "menu", MAX_URL);
    } else if ((a = cachemgrFindAction(request)) == NULL) {
	debug(16, 0) ("cachemgrParse: action '%s' not found\n", request);
	return NULL;
    }
    mgr = xcalloc(1, sizeof(cachemgrStateData));
    mgr->passwd = xstrdup(t == 3 ? password : "nopassword");
    mgr->action = xstrdup(request);
    return mgr;
}

/*
 * return 0 if mgr->password is good
 */
static int
cachemgrCheckPassword(cachemgrStateData * mgr)
{
    char *pwd = cachemgrPasswdGet(Config.passwd_list, mgr->action);
    action_table *a = cachemgrFindAction(mgr->action);
    assert(a != NULL);
    if (pwd == NULL)
	return a->pw_req_flag;
    if (strcmp(pwd, "disable") == 0)
	return 1;
    if (strcmp(pwd, "none") == 0)
	return 0;
    return strcmp(pwd, mgr->passwd);
}

static void
cachemgrStateFree(cachemgrStateData *mgr)
{
	safe_free(mgr->action);
	safe_free(mgr->passwd);
	xfree(mgr);
}

void
cachemgrStart(int fd, StoreEntry * entry)
{
    cachemgrStateData *mgr = NULL;
    ErrorState *err = NULL;
    char *hdr;
    action_table *a;
    debug(16, 3) ("objectcacheStart: '%s'\n", storeUrl(entry));
    if ((mgr = cachemgrParse(storeUrl(entry))) == NULL) {
	err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	entry->expires = squid_curtime;
	return;
    }
    mgr->entry = entry;
    entry->expires = squid_curtime;
    debug(16, 1) ("CACHEMGR: %s requesting '%s'\n",
	fd_table[fd].ipaddr, mgr->action);
    /* Check password */
    if (cachemgrCheckPassword(mgr) != 0) {
	cachemgrStateFree(mgr);
	debug(16, 1) ("WARNING: Incorrect Cachemgr Password!\n");
	err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND);
	errorAppendEntry(entry, err);
	entry->expires = squid_curtime;
	storeComplete(entry);
	return;
    }
    /* retrieve object requested */
    a = cachemgrFindAction(mgr->action);
    assert(a != NULL);
    storeBuffer(entry);
    hdr = httpReplyHeader((double) 1.0,
	HTTP_OK,
	"text/plain",
	-1,			/* Content-Length */
	squid_curtime,		/* LMT */
	squid_curtime);
    storeAppend(entry, hdr, strlen(hdr));
    storeAppend(entry, "\r\n", 2);
    a->handler(entry);
    storeBufferFlush(entry);
    storeComplete(entry);
    cachemgrStateFree(mgr);
}

static void
cachemgrShutdown(StoreEntry * entryunused)
{
    debug(16, 0) ("Shutdown by command.\n");
    shut_down(0);
}

static void
cachemgrMenu(StoreEntry *sentry)
{
	action_table *a;
	for (a = ActionTable; a != NULL; a = a->next) {
		storeAppendPrintf(sentry, " %-22s\t%s\n", a->action, a->desc);
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

void
cachemgrInit(void)
{
    cachemgrRegister("menu",
	"This Cachemanager Menu",
	cachemgrMenu, 0);
    cachemgrRegister("shutdown",
	"Shut Down the Squid Process",
	cachemgrShutdown, 1);
}
