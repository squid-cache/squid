static char rcsid[] = "$Id: http.cc,v 1.1 1996/02/22 06:23:55 wessels Exp $";
/* 
 *  File:         http.c
 *  Description:  state machine for http retrieval protocol.  
 *                Based on John's gopher retrieval module.
 *  Author:       Anawat Chankhunthod, USC
 *  Created:      Tue May 28 10:57:11 1994
 *  Language:     C
 **********************************************************************
 *  Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *    The Harvest software was developed by the Internet Research Task
 *    Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *          Mic Bowman of Transarc Corporation.
 *          Peter Danzig of the University of Southern California.
 *          Darren R. Hardy of the University of Colorado at Boulder.
 *          Udi Manber of the University of Arizona.
 *          Michael F. Schwartz of the University of Colorado at Boulder.
 *          Duane Wessels of the University of Colorado at Boulder.
 *  
 *    This copyright notice applies to software in the Harvest
 *    ``src/'' directory only.  Users should consult the individual
 *    copyright notices in the ``components/'' subdirectories for
 *    copyright information about other software bundled with the
 *    Harvest source code distribution.
 *  
 *  TERMS OF USE
 *    
 *    The Harvest software may be used and re-distributed without
 *    charge, provided that the software origin and research team are
 *    cited in any use of the system.  Most commonly this is
 *    accomplished by including a link to the Harvest Home Page
 *    (http://harvest.cs.colorado.edu/) from the query page of any
 *    Broker you deploy, as well as in the query result pages.  These
 *    links are generated automatically by the standard Broker
 *    software distribution.
 *    
 *    The Harvest software is provided ``as is'', without express or
 *    implied warranty, and with no support nor obligation to assist
 *    in its use, correction, modification or enhancement.  We assume
 *    no liability with respect to the infringement of copyrights,
 *    trade secrets, or any patents, and are not responsible for
 *    consequential damages.  Proper use of the Harvest software is
 *    entirely the responsibility of the user.
 *  
 *  DERIVATIVE WORKS
 *  
 *    Users may make derivative works from the Harvest software, subject 
 *    to the following constraints:
 *  
 *      - You must include the above copyright notice and these 
 *        accompanying paragraphs in all forms of derivative works, 
 *        and any documentation and other materials related to such 
 *        distribution and use acknowledge that the software was 
 *        developed at the above institutions.
 *  
 *      - You must notify IRTF-RD regarding your distribution of 
 *        the derivative work.
 *  
 *      - You must clearly notify users that your are distributing 
 *        a modified version and not the original Harvest software.
 *  
 *      - Any derivative product is also subject to these copyright 
 *        and use restrictions.
 *  
 *    Note that the Harvest software is NOT in the public domain.  We
 *    retain copyright, as specified above.
 *  
 *  HISTORY OF FREE SOFTWARE STATUS
 *  
 *    Originally we required sites to license the software in cases
 *    where they were going to build commercial products/services
 *    around Harvest.  In June 1995 we changed this policy.  We now
 *    allow people to use the core Harvest software (the code found in
 *    the Harvest ``src/'' directory) for free.  We made this change
 *    in the interest of encouraging the widest possible deployment of
 *    the technology.  The Harvest software is really a reference
 *    implementation of a set of protocols and formats, some of which
 *    we intend to standardize.  We encourage commercial
 *    re-implementations of code complying to this set of standards.  
 *  
 *  
 */
#include "config.h"
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ansihelp.h"
#include "comm.h"
#include "store.h"
#include "stat.h"
#include "url.h"
#include "ipcache.h"
#include "cache_cf.h"
#include "ttl.h"
#include "icp.h"
#include "util.h"

#define HTTP_PORT         80
#define HTTP_DELETE_GAP   (64*1024)

extern int errno;
extern char *dns_error_message;
extern time_t cached_curtime;

typedef struct _httpdata {
    StoreEntry *entry;
    char host[HARVESTHOSTNAMELEN + 1];
    int port;
    char *type;
    char *mime_hdr;
    char type_id;
    char request[MAX_URL + 1];
    char *icp_page_ptr;		/* Used to send proxy-http request: 
				 * put_free_8k_page(me) if the lifetime
				 * expires */
    char *icp_rwd_ptr;		/* When a lifetime expires during the
				 * middle of an icpwrite, don't lose the
				 * icpReadWriteData */
} HttpData;

extern char *tmp_error_buf;

char *HTTP_OPS[] =
{"GET", "POST", "HEAD", ""};

int http_url_parser(url, host, port, request)
     char *url;
     char *host;
     int *port;
     char *request;
{
    static char hostbuf[MAX_URL];
    static char atypebuf[MAX_URL];
    int t;

    /* initialize everything */
    (*port) = 0;
    atypebuf[0] = hostbuf[0] = request[0] = host[0] = '\0';

    t = sscanf(url, "%[a-zA-Z]://%[^/]%s", atypebuf, hostbuf, request);
    if ((t < 2) || (strcasecmp(atypebuf, "http") != 0)) {
	return -1;
    } else if (t == 2) {
	strcpy(request, "/");
    }
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = HTTP_PORT;
    return 0;
}

int httpCachable(url, type, mime_hdr)
     char *url;
     char *type;
     char *mime_hdr;
{
    stoplist *p;

    /* GET and HEAD are cachable. Others are not. */
    if (((strncasecmp(type, "GET", 3) != 0)) &&
	(strncasecmp(type, "HEAD", 4) != 0))
	return 0;

    /* url's requiring authentication are uncachable */
    if (mime_hdr && (strstr(mime_hdr, "Authorization")))
	return 0;

    /* scan stop list */
    p = http_stoplist;
    while (p) {
	if (strstr(url, p->key))
	    return 0;
	p = p->next;
    }

    /* else cachable */
    return 1;
}

/* This will be called when timeout on read. */
void httpReadReplyTimeout(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(4, "httpReadReplyTimeout: FD %d: <URL:%s>\n", fd, entry->url);
    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"HTTP",
	103,
	"Read timeout",
	"The Network/Remote site may be down.  Try again later.",
	HARVEST_VERSION,
	comm_hostname());

    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    if (data->icp_page_ptr) {
	put_free_8k_page(data->icp_page_ptr);
	data->icp_page_ptr = NULL;
    }
    storeAbort(entry, tmp_error_buf);
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    comm_close(fd);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_103",		/* HTTP READ TIMEOUT */
	data->type ? data->type : "NULL");
#endif
    safe_free(data);
}

/* This will be called when socket lifetime is expired. */
void httpLifetimeExpire(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(4, "httpLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);

    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"HTTP",
	110,
	"Transaction Timeout",
	"The Network/Remote site may be down or too slow.  Try again later.",
	HARVEST_VERSION,
	comm_hostname());

    if (data->icp_page_ptr) {
	put_free_8k_page(data->icp_page_ptr);
	data->icp_page_ptr = NULL;
    }
    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    storeAbort(entry, tmp_error_buf);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    comm_close(fd);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_110",		/* HTTP LIFETIME EXPIRE */
	data->type ? data->type : "NULL");
#endif
    safe_free(data);
}



/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
void httpReadReply(fd, data)
     int fd;
     HttpData *data;
{
    static char buf[4096];
    int len;
    int clen;
    int off;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    clen = store_mem_obj(entry, e_current_len);
	    off = store_mem_obj(entry, e_lowest_offset);
	    if ((clen - off) > HTTP_DELETE_GAP) {
		debug(3, "httpReadReply: Read deferred for Object: %s\n",
		    entry->key);
		debug(3, "                Current Gap: %d bytes\n",
		    clen - off);

		/* reschedule, so it will be automatically reactivated
		 * when Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) httpReadReply,
		    (caddr_t) data);

/* don't install read timeout until we are below the GAP */
#ifdef INSTALL_READ_TIMEOUT_ABOVE_GAP
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) httpReadReplyTimeout,
		    (caddr_t) data,
		    getReadTimeout());
#else
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (caddr_t) NULL,
		    (time_t) 0);
#endif
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"HTTP",
		119,
		"No Client",
		"All Clients went away before tranmission is complete and object is too big to cache.",
		HARVEST_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
	    comm_close(fd);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_119",	/* HTTP NO CLIENTS, BIG OBJ */
		data->type ? data->type : "NULL");
#endif
	    safe_free(data);
	    return;
	}
    }
    len = read(fd, buf, 4096);
    debug(5, "httpReadReply: FD %d: len %d.\n", fd, len);

    if (len < 0 || ((len == 0) && (store_mem_obj(entry, e_current_len) == 0))) {
	/* XXX we we should log when len==0 and current_len==0 */
	debug(2, "httpReadReply: FD %d: read failure: %s.\n",
	    fd, xstrerror());
	if (errno == ECONNRESET) {
	    /* Connection reset by peer */
	    /* consider it as a EOF */
	    if (!(entry->flag & DELETE_BEHIND))
		entry->expires = cached_curtime + ttlSet(entry);
	    sprintf(tmp_error_buf, "\n<p>Warning: The Remote Server sent RESET at the end of transmission.\n");
	    storeAppend(entry, tmp_error_buf, strlen(tmp_error_buf));
	    storeComplete(entry);
	} else {
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"HTTP",
		105,
		"Read error",
		"Network/Remote site is down.  Try again later.",
		HARVEST_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
	}
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_105",		/* HTTP READ ERROR */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	if (!(entry->flag & DELETE_BEHIND))
	    entry->expires = cached_curtime + ttlSet(entry);
	storeComplete(entry);
	comm_close(fd);
	safe_free(data);
    } else if (((store_mem_obj(entry, e_current_len) + len) > getHttpMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);

	storeAppend(entry, buf, len);
	comm_set_select_handler(fd, COMM_SELECT_READ,
	    (PF) httpReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());

    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we get */
	storeAppend(entry, buf, len);
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    107,
	    "Client Aborted",
	    "Client(s) dropped connection before transmission is complete.\nObject fetching is aborted.\n",
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_107",		/* HTTP CLIENT ABORT */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd, COMM_SELECT_READ,
	    (PF) httpReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void httpSendComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     HttpData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(5, "httpSendComplete: FD %d: size %d: errflag %d.\n",
	fd, size, errflag);

    if (buf) {
	put_free_8k_page(buf);	/* Allocated by httpSendRequest. */
	buf = NULL;
    }
    data->icp_page_ptr = NULL;	/* So lifetime expire doesn't re-free */
    data->icp_rwd_ptr = NULL;	/* Don't double free in lifetimeexpire */

    if (errflag) {
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    101,
	    "Cannot connect to the original site",
	    "The remote site may be down.",
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_101",		/* HTTP CONNECT FAIL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return;
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd, COMM_SELECT_READ,
	    (PF) httpReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
	    (PF) httpReadReplyTimeout, (caddr_t) data, getReadTimeout());
	comm_set_fd_lifetime(fd, -1);	/* disable lifetime DPW */

    }
}

/* This will be called when connect completes. Write request. */
void httpSendRequest(fd, data)
     int fd;
     HttpData *data;
{
    char *xbuf = NULL;
    char *ybuf = NULL;
    char *buf = NULL;
    char *t = NULL;
    char *post_buf = NULL;
    static char *crlf = "\r\n";
    static char *HARVEST_PROXY_TEXT = "via Harvest Cache version";
    int len = 0;
    int buflen;

    debug(5, "httpSendRequest: FD %d: data %p.\n", fd, data);
    buflen = strlen(data->type) + strlen(data->request);
    if (data->mime_hdr)
	buflen += strlen(data->mime_hdr);
    buflen += 512;		/* lots of extra */

    if (!strcasecmp(data->type, "POST") && data->mime_hdr) {
	if ((t = strstr(data->mime_hdr, "\r\n\r\n"))) {
	    post_buf = xstrdup(t + 4);
	    *(t + 4) = '\0';
	}
    }
    /* Since we limit the URL read to a 4K page, I doubt that the
     * mime header could be longer than an 8K page */
    buf = (char *) get_free_8k_page();
    data->icp_page_ptr = buf;
    if (buflen > DISK_PAGE_SIZE) {
	debug(0, "Mime header length %d is breaking ICP code\n", buflen);
    }
    memset(buf, '\0', buflen);

    sprintf(buf, "%s %s ", data->type, data->request);
    len = strlen(buf);
    if (data->mime_hdr) {	/* we have to parse the MIME header */
	xbuf = xstrdup(data->mime_hdr);
	for (t = strtok(xbuf, crlf); t; t = strtok(NULL, crlf)) {
	    if (strncasecmp(t, "User-Agent:", 11) == 0) {
		ybuf = (char *) get_free_4k_page();
		memset(ybuf, '\0', SM_PAGE_SIZE);
		sprintf(ybuf, "%s %s %s", t, HARVEST_PROXY_TEXT, HARVEST_VERSION);
		t = ybuf;
	    }
	    if (strncasecmp(t, "If-Modified-Since:", 18) == 0)
		continue;
	    if (len + (int) strlen(t) > buflen - 10)
		continue;
	    strcat(buf, t);
	    strcat(buf, crlf);
	    len += strlen(t) + 2;
	}
	xfree(xbuf);
	if (ybuf) {
	    put_free_4k_page(ybuf);
	    ybuf = NULL;
	}
    }
    strcat(buf, crlf);
    len += 2;
    if (post_buf) {
	strcat(buf, post_buf);
	len += strlen(post_buf);
	xfree(post_buf);
    }
    debug(6, "httpSendRequest: FD %d: buf '%s'\n", fd, buf);
    data->icp_rwd_ptr = icpWrite(fd, buf, len, 30, httpSendComplete, data);
}

void httpConnInProgress(fd, data)
     int fd;
     HttpData *data;
{
    StoreEntry *entry = data->entry;

    if (comm_connect(fd, data->host, data->port) != COMM_OK)
	switch (errno) {
	case EINPROGRESS:
	case EALREADY:
	    /* schedule this handler again */
	    comm_set_select_handler(fd,
		COMM_SELECT_WRITE,
		(PF) httpConnInProgress,
		(caddr_t) data);
	    return;
	case EISCONN:
	    break;		/* cool, we're connected */
	default:
	    comm_close(fd);
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"HTTP",
		104,
		"Cannot connect to the original site",
		"The remote site may be down.",
		HARVEST_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_104",	/* HTTP CONNECT FAIL */
		data->type ? data->type : "NULL");
#endif
	    safe_free(data);
	    return;
	}
    /* Call the real write handler, now that we're fully connected */
    comm_set_select_handler(fd, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
}

int proxyhttpStart(e, url, entry)
     edge *e;
     char *url;
     StoreEntry *entry;
{

    /* Create state structure. */
    int sock, status;
    HttpData *data = (HttpData *) xmalloc(sizeof(HttpData));

    debug(3, "proxyhttpStart: <URL:%s>\n", url);
    debug(10, "proxyhttpStart: HTTP request header:\n%s\n",
	store_mem_obj(entry, mime_hdr));

    memset(data, '\0', sizeof(HttpData));
    data->entry = entry;

    strncpy(data->request, url, sizeof(data->request) - 1);
    data->type = HTTP_OPS[entry->type_id];
    data->port = e->ascii_port;
    data->mime_hdr = store_mem_obj(entry, mime_hdr);
    strncpy(data->host, e->host, sizeof(data->host) - 1);

    if (e->proxy_only)
	storeStartDeleteBehind(entry);

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(4, "proxyhttpStart: Failed because we're out of sockets.\n");
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    111,
	    "Cached short of file-descriptors, sorry",
	    "",
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_111",		/* HTTP NO FD'S */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(4, "proxyhttpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	comm_close(sock);
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    102,
	    "DNS name lookup failure",
	    dns_error_message,
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_102",		/* HTTP DNS FAIL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    comm_close(sock);
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"HTTP",
		104,
		"Cannot connect to the original site",
		"The remote site may be down.",
		HARVEST_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_104",	/* HTTP CONNECT FAIL */
		data->type ? data->type : "NULL");
#endif
	    safe_free(data);
	    e->last_fail_time = cached_curtime;
	    e->neighbor_up = 0;
	    return COMM_ERROR;
	} else {
	    debug(5, "proxyhttpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (caddr_t) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (caddr_t) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
    return COMM_OK;

}

int httpStart(unusedfd, url, type, mime_hdr, entry)
     int unusedfd;
     char *url;
     char *type;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    HttpData *data = (HttpData *) xmalloc(sizeof(HttpData));

    debug(3, "httpStart: %s <URL:%s>\n", type, url);
    debug(10, "httpStart: mime_hdr '%s'\n", mime_hdr);

    memset(data, '\0', sizeof(HttpData));
    data->entry = entry;
    data->type = type;
    data->mime_hdr = mime_hdr;

    /* Parse url. */
    if (http_url_parser(url, data->host, &data->port, data->request)) {
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    110,
	    "Invalid URL syntax:  Cannot parse.",
	    "Contact your system administrator for further help.",
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_110",		/* HTTP INVALID URL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(4, "httpStart: Failed because we're out of sockets.\n");
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    111,
	    "Cached short of file-descriptors, sorry",
	    "",
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_111",		/* HTTP NO FD'S */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(4, "httpstart: Called without IP entry in ipcache. OR lookup failed.\n");
	comm_close(sock);
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "HTTP",
	    108,
	    "DNS name lookup failure",
	    dns_error_message,
	    HARVEST_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_108",		/* HTTP DNS FAIL */
	    data->type ? data->type : "NULL");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    comm_close(sock);
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"HTTP",
		109,
		"Cannot connect to the original site",
		"The remote site may be down.",
		HARVEST_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_109",	/* HTTP CONNECT FAIL */
		data->type ? data->type : "NULL");
#endif
	    safe_free(data);
	    return COMM_ERROR;
	} else {
	    debug(5, "httpStart: FD %d: EINPROGRESS.\n", sock);
	    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
		(PF) httpLifetimeExpire, (caddr_t) data);
	    comm_set_select_handler(sock, COMM_SELECT_WRITE,
		(PF) httpConnInProgress, (caddr_t) data);
	    return COMM_OK;
	}
    }
    /* Install connection complete handler. */
    fd_note(sock, entry->url);
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) httpLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) httpSendRequest, (caddr_t) data);
    return COMM_OK;
}
