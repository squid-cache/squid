
/*
 * $Id: client_side.cc,v 1.114 1997/06/26 22:41:40 wessels Exp $
 *
 * DEBUG: section 33    Client-side Routines
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

static RH clientRedirectDone;
static STCB icpHandleIMSReply;
static int clientGetsOldEntry _PARAMS((StoreEntry * new, StoreEntry * old, request_t * request));
static int checkAccelOnly _PARAMS((clientHttpRequest *));

#if USE_PROXY_AUTH
/* ProxyAuth code by Jon Thackray <jrmt@uk.gdscorp.com> */
/* return 1 if allowed, 0 if denied */
static int
clientProxyAuthCheck(clientHttpRequest * http)
{
    const char *proxy_user;

    /* Check that the user is allowed to access via this proxy-cache
     * don't restrict if they're accessing a local domain or
     * an object of type cacheobj:// */
    if (Config.proxyAuth.File == NULL)
	return 1;
    if (urlParseProtocol(http->url) == PROTO_CACHEOBJ)
	return 1;

    if (Config.proxyAuth.IgnoreDomains) {
	if (aclMatchRegex(Config.proxyAuth.IgnoreDomains, http->request->host)) {
	    debug(33, 2) ("clientProxyAuthCheck: host \"%s\" matched proxyAuthIgnoreDomains\n", http->request->host);
	    return 1;
	}
    }
    proxy_user = proxyAuthenticate(http->request_hdr);
    xstrncpy(http->ident.ident, proxy_user, ICP_IDENT_SZ);
    debug(33, 6) ("clientProxyAuthCheck: user = %s\n", http->ident.ident);

    if (strcmp(http->ident.ident, dash_str) == 0)
	return 0;
    return 1;
}
#endif /* USE_PROXY_AUTH */

static int
checkAccelOnly(clientHttpRequest * http)
{
    /* return TRUE if someone makes a proxy request to us and
     * we are in httpd-accel only mode */
    if (!httpd_accel_mode)
	return 0;
    if (Config.Accel.withProxy)
	return 0;
    if (http->request->protocol == PROTO_CACHEOBJ)
	return 0;
    if (http->accel)
	return 0;
    return 1;
}

void
clientAccessCheck(void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    char *browser;
    if (Config.identLookup && conn->ident.state == IDENT_NONE) {
	identStart(-1, conn, clientAccessCheck);
	return;
    }
#if USE_PROXY_AUTH
    if (clientProxyAuthCheck(http) == 0) {
	char *wbuf = NULL;
	int fd = conn->fd;
	debug(33, 4) ("Proxy Denied: %s\n", http->url);
	http->log_type = ERR_PROXY_DENIED;
	http->http_code = 407;
	wbuf = xstrdup(proxy_denied_msg(http->http_code,
		http->request->method,
		http->url,
		fd_table[fd].ipaddr));
	icpSendERROR(fd, http->log_type, wbuf, conn, http->http_code);
	safe_free(http->aclChecklist);
	return;
    }
#endif /* USE_PROXY_AUTH */
    if (checkAccelOnly(http)) {
	clientAccessCheckDone(0, http);
	return;
    }
    browser = mime_get_header(http->request->headers, "User-Agent");
    http->acl_checklist = aclChecklistCreate(Config.accessList.HTTP,
	http->request,
	conn->peer.sin_addr,
	browser,
	conn->ident.ident);
    aclNBCheck(http->acl_checklist, clientAccessCheckDone, http);
}

void
clientAccessCheckDone(int answer, void *data)
{
    clientHttpRequest *http = data;
    ConnStateData *conn = http->conn;
    int fd = conn->fd;
    char *buf = NULL;
    char *redirectUrl = NULL;
    debug(33, 5) ("clientAccessCheckDone: '%s' answer=%d\n", http->url, answer);
    http->acl_checklist = NULL;
    if (answer) {
	urlCanonical(http->request, http->url);
	if (http->redirect_state != REDIRECT_NONE)
	    fatal_dump("clientAccessCheckDone: wrong redirect_state");
	http->redirect_state = REDIRECT_PENDING;
	redirectStart(http, clientRedirectDone, http);
    } else {
	debug(33, 5) ("Access Denied: %s\n", http->url);
	redirectUrl = aclGetDenyInfoUrl(&Config.denyInfoList, AclMatchedName);
	if (redirectUrl) {
	    http->http_code = 302,
		buf = access_denied_redirect(http->http_code,
		http->request->method,
		http->url,
		fd_table[fd].ipaddr,
		redirectUrl);
	} else {
	    http->http_code = 400;
	    buf = access_denied_msg(http->http_code,
		http->request->method,
		http->url,
		fd_table[fd].ipaddr);
	}
	icpSendERROR(fd, LOG_TCP_DENIED, buf, http, http->http_code);
    }
}

static void
clientRedirectDone(void *data, char *result)
{
    clientHttpRequest *http = data;
    int fd = http->conn->fd;
    request_t *new_request = NULL;
    request_t *old_request = http->request;
    debug(33, 5) ("clientRedirectDone: '%s' result=%s\n", http->url,
	result ? result : "NULL");
    if (http->redirect_state != REDIRECT_PENDING)
	fatal_dump("clientRedirectDone: wrong redirect_state");
    http->redirect_state = REDIRECT_DONE;
    if (result)
	new_request = urlParse(old_request->method, result);
    if (new_request) {
	safe_free(http->url);
	http->url = xstrdup(result);
	new_request->http_ver = old_request->http_ver;
	new_request->headers = old_request->headers;
	new_request->headers_sz = old_request->headers_sz;
	requestUnlink(old_request);
	http->request = requestLink(new_request);
	urlCanonical(http->request, http->url);
    }
    icpParseRequestHeaders(http);
    fd_note(fd, http->url);
    icpProcessRequest(fd, http);
}

#if USE_PROXY_AUTH
/* Check the modification time on the file that holds the proxy
 * passwords every 'n' seconds, and if it has changed, reload it
 */
#define CHECK_PROXY_FILE_TIME 300

const char *
proxyAuthenticate(const char *headers)
{
    /* Keep the time measurements and the hash
     * table of users and passwords handy */
    static time_t last_time = 0;
    static time_t change_time = 0;
    static hash_table *validated = NULL;
    static char *passwords = NULL;
    LOCAL_ARRAY(char, sent_user, ICP_IDENT_SZ);

    char *s = NULL;
    char *sent_userandpw = NULL;
    char *user = NULL;
    char *passwd = NULL;
    char *clear_userandpw = NULL;
    struct stat buf;
    int i;
    hash_link *hashr = NULL;
    FILE *f = NULL;

    /* Look for Proxy-authorization: Basic in the
     * headers sent by the client
     */
    if ((s = mime_get_header(headers, "Proxy-authorization:")) == NULL) {
	debug(33, 5) ("proxyAuthenticate: Can't find authorization header\n");
	return (dash_str);
    }
    /* Skip the 'Basic' part */
    s += strlen(" Basic");
    sent_userandpw = xstrdup(s);
    strtok(sent_userandpw, "\n");	/* Trim trailing \n before decoding */
    clear_userandpw = uudecode(sent_userandpw);
    xfree(sent_userandpw);

    xstrncpy(sent_user, clear_userandpw, ICP_IDENT_SZ);
    strtok(sent_user, ":");	/* Remove :password */
    debug(33, 5) ("proxyAuthenticate: user = %s\n", sent_user);

    /* Look at the Last-modified time of the proxy.passwords
     * file every five minutes, to see if it's been changed via
     * a cgi-bin script, etc. If so, reload a fresh copy into memory
     */

    if ((squid_curtime - last_time) > CHECK_PROXY_FILE_TIME) {
	debug(33, 5) ("proxyAuthenticate: checking password file %s hasn't changed\n", Config.proxyAuth.File);

	if (stat(Config.proxyAuth.File, &buf) == 0) {
	    if (buf.st_mtime != change_time) {
		debug(33, 0) ("proxyAuthenticate: reloading changed proxy authentication password file %s \n", Config.proxyAuth.File);
		change_time = buf.st_mtime;

		if (validated != 0) {
		    debug(33, 5) ("proxyAuthenticate: invalidating old entries\n");
		    for (i = 0, hashr = hash_first(validated); hashr; hashr = hash_next(validated)) {
			debug(33, 6) ("proxyAuthenticate: deleting %s\n", hashr->key);
			hash_delete(validated, hashr->key);
		    }
		} else {
		    /* First time around, 7921 should be big enough */
		    if ((validated = hash_create(urlcmp, 7921, hash_string)) < 0) {
			debug(33, 1) ("ERK: can't create hash table. Turning auth off");
			xfree(Config.proxyAuth.File);
			Config.proxyAuth.File = NULL;
			return (dash_str);
		    }
		}

		passwords = xmalloc((size_t) buf.st_size + 2);
		f = fopen(Config.proxyAuth.File, "r");
		fread(passwords, (size_t) buf.st_size, 1, f);
		*(passwords + buf.st_size) = '\0';
		strcat(passwords, "\n");
		fclose(f);

		user = strtok(passwords, ":");
		passwd = strtok(NULL, "\n");

		debug(33, 5) ("proxyAuthenticate: adding new passwords to hash table\n");
		while (user != NULL) {
		    if (strlen(user) > 1 && strlen(passwd) > 1) {
			debug(33, 6) ("proxyAuthenticate: adding %s, %s to hash table\n", user, passwd);
			hash_insert(validated, xstrdup(user), xstrdup(passwd));
		    }
		    user = strtok(NULL, ":");
		    passwd = strtok(NULL, "\n");
		}

		xfree(passwords);
	    }
	} else {
	    debug(33, 1) ("ERK: can't access proxy_auth file %s. Turning authentication off", Config.proxyAuth.File);
	    xfree(Config.proxyAuth.File);
	    Config.proxyAuth.File = NULL;
	    return (dash_str);
	}
    }
    last_time = squid_curtime;

    hashr = hash_lookup(validated, sent_user);
    if (hashr == NULL) {
	/* User doesn't exist; deny them */
	debug(33, 4) ("proxyAuthenticate: user %s doesn't exist\n", sent_user);
	xfree(clear_userandpw);
	return (dash_str);
    }
    passwd = strstr(clear_userandpw, ":");
    passwd++;

    /* See if we've already validated them */
    if (strcmp(hashr->item, passwd) == 0) {
	debug(33, 5) ("proxyAuthenticate: user %s previously validated\n", sent_user);
	xfree(clear_userandpw);
	return sent_user;
    }
    if (strcmp(hashr->item, (char *) crypt(passwd, hashr->item))) {
	/* Passwords differ, deny access */
	debug(33, 4) ("proxyAuthenticate: authentication failed: user %s passwords differ\n", sent_user);
	xfree(clear_userandpw);
	return (dash_str);
    }
    debug(33, 5) ("proxyAuthenticate: user %s validated\n", sent_user);
    hash_delete(validated, sent_user);
    hash_insert(validated, xstrdup(sent_user), xstrdup(passwd));

    xfree(clear_userandpw);
    return (sent_user);
}
#endif /* USE_PROXY_AUTH */

void
icpProcessExpired(int fd, void *data)
{
    clientHttpRequest *http = data;
    char *url = http->url;
    StoreEntry *entry = NULL;

    debug(33, 3) ("icpProcessExpired: FD %d '%s'\n", fd, http->url);

    BIT_SET(http->request->flags, REQ_REFRESH);
    http->old_entry = http->entry;
    entry = storeCreateEntry(url,
	http->request->flags,
	http->request->method);
    /* NOTE, don't call storeLockObject(), storeCreateEntry() does it */
    storeClientListAdd(entry, http);
    storeClientListAdd(http->old_entry, http);

    entry->lastmod = http->old_entry->lastmod;
    debug(33, 5) ("icpProcessExpired: setting lmt = %d\n",
	entry->lastmod);

    entry->refcount++;		/* EXPIRED CASE */
    http->entry = entry;
    http->out.offset = 0;
    protoDispatch(fd, http->entry, http->request);
    /* Register with storage manager to receive updates when data comes in. */
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	4096,
	get_free_4k_page(),
	icpHandleIMSReply,
	http);
}

static int
clientGetsOldEntry(StoreEntry * new_entry, StoreEntry * old_entry, request_t * request)
{
    /* If the reply is anything but "Not Modified" then
     * we must forward it to the client */
    if (new_entry->mem_obj->reply->code != 304) {
	debug(33, 5) ("clientGetsOldEntry: NO, reply=%d\n", new_entry->mem_obj->reply->code);
	return 0;
    }
    /* If the client did not send IMS in the request, then it
     * must get the old object, not this "Not Modified" reply */
    if (!BIT_TEST(request->flags, REQ_IMS)) {
	debug(33, 5) ("clientGetsOldEntry: YES, no client IMS\n");
	return 1;
    }
    /* If the client IMS time is prior to the entry LASTMOD time we
     * need to send the old object */
    if (modifiedSince(old_entry, request)) {
	debug(33, 5) ("clientGetsOldEntry: YES, modified since %d\n", request->ims);
	return 1;
    }
    debug(33, 5) ("clientGetsOldEntry: NO, new one is fine\n");
    return 0;
}



static void
icpHandleIMSReply(void *data, char *buf, ssize_t size)
{
    clientHttpRequest *http = data;
    int fd = http->conn->fd;
    StoreEntry *entry = http->entry;
    MemObject *mem = entry->mem_obj;
    int unlink_request = 0;
    StoreEntry *oldentry;
    debug(33, 3) ("icpHandleIMSReply: FD %d '%s'\n", fd, entry->url);
    /* unregister this handler */
    if (entry->store_status == STORE_ABORTED) {
	debug(33, 3) ("icpHandleIMSReply: ABORTED/%s '%s'\n",
	    log_tags[entry->mem_obj->abort_code], entry->url);
	/* We have an existing entry, but failed to validate it,
	 * so send the old one anyway */
	http->log_type = LOG_TCP_REFRESH_FAIL_HIT;
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	entry = http->entry = http->old_entry;
	entry->refcount++;
    } else if (mem->reply->code == 0) {
	debug(33, 3) ("icpHandleIMSReply: Incomplete headers for '%s'\n",
	    entry->url);
	storeClientCopy(entry,
	    http->out.offset + size,
	    http->out.offset,
	    4096,
	    get_free_4k_page(),
	    icpHandleIMSReply,
	    http);
	return;
    } else if (clientGetsOldEntry(entry, http->old_entry, http->request)) {
	/* We initiated the IMS request, the client is not expecting
	 * 304, so put the good one back.  First, make sure the old entry
	 * headers have been loaded from disk. */
	oldentry = http->old_entry;
	http->log_type = LOG_TCP_REFRESH_HIT;
	if (oldentry->mem_obj->request == NULL) {
	    oldentry->mem_obj->request = requestLink(mem->request);
	    unlink_request = 1;
	}
	memcpy(oldentry->mem_obj->reply, entry->mem_obj->reply, sizeof(struct _http_reply));
	storeTimestampsSet(oldentry);
	storeUnregister(entry, http);
	storeUnlockObject(entry);
	entry = http->entry = oldentry;
	entry->timestamp = squid_curtime;
	if (unlink_request) {
	    requestUnlink(entry->mem_obj->request);
	    entry->mem_obj->request = NULL;
	}
    } else {
	/* the client can handle this reply, whatever it is */
	http->log_type = LOG_TCP_REFRESH_MISS;
	if (mem->reply->code == 304) {
	    http->old_entry->timestamp = squid_curtime;
	    http->old_entry->refcount++;
	    http->log_type = LOG_TCP_REFRESH_HIT;
	}
	storeUnregister(http->old_entry, http);
	storeUnlockObject(http->old_entry);
#if DONT_USE_VM
	file_close(http->swapin_fd);
	http->swapin_fd = storeOpenSwapFileRead(entry);
	if (http->swapin_fd < 0)
	    fatal_dump("icpHandleIMSReply: storeOpenSwapFileRead() failed\n");
#endif
    }
    http->old_entry = NULL;	/* done with old_entry */
    storeClientCopy(entry,
	http->out.offset,
	http->out.offset,
	4096,
	get_free_4k_page(),
	icpSendMoreData,
	http);
}

int
modifiedSince(StoreEntry * entry, request_t * request)
{
    int object_length;
    MemObject *mem = entry->mem_obj;
    debug(33, 3) ("modifiedSince: '%s'\n", entry->url);
    if (entry->lastmod < 0)
	return 1;
    /* Find size of the object */
    if (mem->reply->content_length)
	object_length = mem->reply->content_length;
    else
	object_length = entry->object_len - mem->reply->hdr_sz;
    if (entry->lastmod > request->ims) {
	debug(33, 3) ("--> YES: entry newer than client\n");
	return 1;
    } else if (entry->lastmod < request->ims) {
	debug(33, 3) ("-->  NO: entry older than client\n");
	return 0;
    } else if (request->imslen < 0) {
	debug(33, 3) ("-->  NO: same LMT, no client length\n");
	return 0;
    } else if (request->imslen == object_length) {
	debug(33, 3) ("-->  NO: same LMT, same length\n");
	return 0;
    } else {
	debug(33, 3) ("--> YES: same LMT, different length\n");
	return 1;
    }
}

char *
clientConstructTraceEcho(clientHttpRequest * http)
{
    LOCAL_ARRAY(char, line, 256);
    LOCAL_ARRAY(char, buf, 8192);
    size_t len;
    memset(buf, '\0', 8192);
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(line, "Date: %s\r\n", mkrfc1123(squid_curtime));
    strcat(buf, line);
    sprintf(line, "Server: Squid/%s\r\n", SQUID_VERSION);
    strcat(buf, line);
    sprintf(line, "Content-Type: message/http\r\n");
    strcat(buf, line);
    strcat(buf, "\r\n");
    len = strlen(buf);
    httpBuildRequestHeader(http->request,
	http->request,
	NULL,			/* entry */
	NULL,			/* in_len */
	buf + len,
	8192 - len,
	http->conn->fd);
    http->log_type = LOG_TCP_MISS;
    http->http_code = 200;
    return buf;
}

void
clientPurgeRequest(clientHttpRequest * http)
{
    char *buf;
    int fd = http->conn->fd;
    LOCAL_ARRAY(char, msg, 8192);
    LOCAL_ARRAY(char, line, 256);
    StoreEntry *entry;
    debug(0, 0) ("Config.Options.enable_purge = %d\n", Config.Options.enable_purge);
    if (!Config.Options.enable_purge) {
	buf = access_denied_msg(http->http_code = 401,
	    http->request->method,
	    http->url,
	    fd_table[fd].ipaddr);
	icpSendERROR(fd, LOG_TCP_DENIED, buf, http, http->http_code);
	return;
    }
    http->log_type = LOG_TCP_MISS;
    if ((entry = storeGet(http->url)) == NULL) {
	sprintf(msg, "HTTP/1.0 404 Not Found\r\n");
	http->http_code = 404;
    } else {
	storeRelease(entry);
	sprintf(msg, "HTTP/1.0 200 OK\r\n");
	http->http_code = 200;
    }
    sprintf(line, "Date: %s\r\n", mkrfc1123(squid_curtime));
    strcat(msg, line);
    sprintf(line, "Server: Squid/%s\r\n", SQUID_VERSION);
    strcat(msg, line);
    strcat(msg, "\r\n");
    comm_write(fd,
	msg,
	strlen(msg),
	icpSendERRORComplete,
	http,
	NULL);
}
