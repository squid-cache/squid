
/*
 * $Id: cache_manager.cc,v 1.7 1998/02/26 18:00:37 wessels Exp $
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
    char *user_name;
    char *passwd;
} cachemgrStateData;

typedef struct _action_table {
    char *action;
    char *desc;
    OBJH *handler;
    int pw_req_flag;
    struct _action_table *next;
} action_table;

static action_table *cachemgrFindAction(const char *action);
#if 0
static cachemgrStateData *cachemgrParse(const char *url);
#else
static cachemgrStateData *cachemgrParseUrl(const char *url);
#endif
static void cachemgrParseHeaders(cachemgrStateData * mgr, const request_t * request);
static int cachemgrCheckPassword(cachemgrStateData *);
static void cachemgrStateFree(cachemgrStateData * mgr);
static char *cachemgrPasswdGet(cachemgr_passwd *, const char *);
static const char *cachemgrActionProtection(const action_table * at);
static OBJH cachemgrShutdown;
static OBJH cachemgrMenu;

action_table *ActionTable = NULL;

void
cachemgrRegister(const char *action, const char *desc, OBJH * handler, int pw_req_flag)
{
    action_table *a;
    action_table **A;
    if (cachemgrFindAction(action) != NULL) {
	debug(16, 3) ("cachemgrRegister: Duplicate '%s'\n", action);
	return;
    }
    a = xcalloc(1, sizeof(action_table));
    a->action = xstrdup(action);
    a->desc = xstrdup(desc);
    a->handler = handler;
    a->pw_req_flag = pw_req_flag;
    for (A = &ActionTable; *A; A = &(*A)->next);
    *A = a;
    debug(16, 3) ("cachemgrRegister: registered %s\n", action);
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
cachemgrParseUrl(const char *url)
{
    int t;
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, request, MAX_URL);
    LOCAL_ARRAY(char, password, MAX_URL);
    action_table *a;
    cachemgrStateData *mgr = NULL;
    const char *prot;
    t = sscanf(url, "cache_object://%[^/]/%[^@]@%s", host, request, password);
    if (t < 2) {
	xstrncpy(request, "menu", MAX_URL);
    } else if ((a = cachemgrFindAction(request)) == NULL) {
	debug(16, 0) ("cachemgrParseUrl: action '%s' not found\n", request);
	return NULL;
    } else {
	prot = cachemgrActionProtection(a);
	if (!strcmp(prot, "disabled") || !strcmp(prot, "hidden")) {
	    debug(16, 0) ("cachemgrParseUrl: action '%s' is %s\n", request, prot);
	    return NULL;
	}
    }
    /* set absent entries to NULL so we can test if they are present later */
    mgr = xcalloc(1, sizeof(cachemgrStateData));
    mgr->user_name = NULL;
    mgr->passwd = t == 3 ? xstrdup(password) : NULL;
    mgr->action = xstrdup(request);
    return mgr;
}

static void
cachemgrParseHeaders(cachemgrStateData * mgr, const request_t * request)
{
    const char *basic_cookie;	/* base 64 _decoded_ user:passwd pair */
    const char *authField;
    const char *passwd_del;
    assert(mgr && request);
    /* this parsing will go away when hdrs are added to request_t @?@ */
    basic_cookie = mime_get_auth(request->headers, "Basic", &authField);
    debug(16, 9) ("cachemgrParseHeaders: got auth: '%s'\n", authField ? authField : "<none>");
    if (!authField)
	return;
    if (!basic_cookie) {
	debug(16, 1) ("cachemgrParseHeaders: unknown auth format in '%s'\n", authField);
	return;
    }
    if (!(passwd_del = strchr(basic_cookie, ':'))) {
	debug(16, 1) ("cachemgrParseHeaders: unknown basic_cookie '%s' format in '%s'\n", basic_cookie, authField);
	return;
    }
    /* found user:password pair, reset old values */
    safe_free(mgr->user_name);
    safe_free(mgr->passwd);
    mgr->user_name = xstrdup(basic_cookie);
    mgr->user_name[passwd_del - basic_cookie] = '\0';
    mgr->passwd = xstrdup(passwd_del + 1);
    /* warning: this prints decoded password which maybe not what you want to do @?@ @?@ */
    debug(16, 9) ("cachemgrParseHeaders: got user: '%s' passwd: '%s'\n", mgr->user_name, mgr->passwd);
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
    xfree(mgr);
}

void
cachemgrStart(int fd, request_t * request, StoreEntry * entry)
{
    cachemgrStateData *mgr = NULL;
    ErrorState *err = NULL;
    action_table *a;
    debug(16, 3) ("objectcacheStart: '%s'\n", storeUrl(entry));
    if ((mgr = cachemgrParseUrl(storeUrl(entry))) == NULL) {
	err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	entry->expires = squid_curtime;
	return;
    }
    mgr->entry = entry;
    entry->expires = squid_curtime;
    debug(16, 5) ("CACHEMGR: %s requesting '%s'\n",
	fd_table[fd].ipaddr, mgr->action);
    /* get additional info from request headers */
    cachemgrParseHeaders(mgr, request);
    if (mgr->user_name && strlen(mgr->user_name))
	debug(16, 1) ("CACHEMGR: %s@%s requesting '%s'\n",
	    mgr->user_name, fd_table[fd].ipaddr, mgr->action);
    else
	debug(16, 1) ("CACHEMGR: %s requesting '%s'\n",
	    fd_table[fd].ipaddr, mgr->action);
    /* Check password */
    if (cachemgrCheckPassword(mgr) != 0) {
#if 0				/* old response, we ask for authentication now */
	cachemgrStateFree(mgr);
	debug(16, 1) ("WARNING: Incorrect Cachemgr Password!\n");
	err = errorCon(ERR_INVALID_URL, HTTP_NOT_FOUND);
	errorAppendEntry(entry, err);
#else
	/* build error message */
	ErrorState *err = errorCon(ERR_CACHE_MGR_ACCESS_DENIED, HTTP_UNAUTHORIZED);
	HttpReply *rep;
	/* warn if user specified incorrect password */
	if (mgr->passwd)
	    debug(16, 1) ("WARNING: CACHEMGR: Incorrect Password (user: %s, action: %s)!\n",
		mgr->user_name ? mgr->user_name : "<unknown>", mgr->action);
	else
	    debug(16, 3) ("CACHEMGR: requesting authentication for action: '%s'.\n",
		mgr->action);
	err->request = requestLink(request);
	rep = errorBuildReply(err);
	errorStateFree(err);
	/* add Authenticate header, use 'action' as a realm because password depends on action */
	httpHeaderSetAuth(&rep->hdr, "Basic", mgr->action);
	/* move info to the mem_obj->reply */
	httpReplyAbsorb(entry->mem_obj->reply, rep);
	/* store the reply */
	httpReplySwapOut(entry->mem_obj->reply, entry);
	cachemgrStateFree(mgr);
#endif
	entry->expires = squid_curtime;
	storeComplete(entry);
	return;
    }
    /* retrieve object requested */
    a = cachemgrFindAction(mgr->action);
    assert(a != NULL);
    storeBuffer(entry);
    {
	HttpReply *rep = httpReplyCreate();
	httpReplySetHeaders(rep, (double) 1.0, HTTP_OK, NULL,
	    "text/plain", -1 /* C-Len */ , squid_curtime /* LMT */ , squid_curtime);
	httpReplySwapOut(rep, entry);
	httpReplyDestroy(rep);
    }
#if 0
    hdr = httpReplyHeader((double) 1.0,
	HTTP_OK,
	"text/plain",
	-1,			/* Content-Length */
	squid_curtime,		/* LMT */
	squid_curtime);
    storeAppend(entry, hdr, strlen(hdr));
    storeAppend(entry, "\r\n", 2);
#endif
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

static const char *
cachemgrActionProtection(const action_table * at)
{
    char *pwd;
    assert(at);
    pwd = cachemgrPasswdGet(Config.passwd_list, at->action);
    if (!pwd)
	return at->pw_req_flag ? "hidden" : "public";
    if (!strcmp(pwd, "disable"))
	return "disabled";
    if (strcmp(pwd, "none") == 0)
	return "public";
    return "protected";
}

static void
cachemgrMenu(StoreEntry * sentry)
{
    action_table *a;
    for (a = ActionTable; a != NULL; a = a->next) {
	storeAppendPrintf(sentry, " %-22s\t%s\t%s\n",
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
