static char rcsid[] = "$Id: wais.cc,v 1.2 1996/02/23 05:41:29 wessels Exp $";
/*
 *  File:         wais.c
 *  Description:  state machine for wais retrieval protocol (just open a
 *                connection to a wais gateway, like the CERN waisd).
 *                Based on John's gopher retrieval module.
 *  Author:       Edward Moy, Xerox PARC
 *  Created:      Tue Jun 20 13:07:42 PDT 1995
 *  Language:     C
 *
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
#if USE_WAIS_RELAY
#include <sys/errno.h>
#include <stdlib.h>
#include <string.h>

#include "ansihelp.h"
#include "comm.h"
#include "store.h"
#include "stat.h"
#include "neighbors.h"
#include "url.h"
#include "ipcache.h"
#include "cache_cf.h"
#include "util.h"

#define  WAIS_DELETE_GAP  (64*1024)

typedef struct _waisdata {
    StoreEntry *entry;
    char host[HARVESTHOSTNAMELEN + 1];
    int port;
    char *type;
    char *mime_hdr;
    char type_id;
    char request[MAX_URL];
} WAISData;

extern char *tmp_error_buf;
extern char *dns_error_message;
extern time_t cached_curtime;

int wais_url_parser(url, host, port, request)
     char *url;
     char *host;
     int *port;
     char *request;
{
    strcpy(host, getWaisRelayHost());
    *port = getWaisRelayPort();
    strcpy(request, url);

    return 0;
}

/* This will be called when timeout on read. */
void waisReadReplyTimeout(fd, data)
     int fd;
     WAISData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(4, "waisReadReplyTimeout: Timeout on %d\n url: %s\n", fd, entry->url);
    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"WAIS",
	403,
	"Read timeout",
	"The Network/Remote site may be down.  Try again later.",
	SQUID_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    comm_close(fd);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_403",		/* WAIS READ TIMEOUT */
	"GET");
#endif
    safe_free(data);
}

/* This will be called when socket lifetime is expired. */
void waisLifetimeExpire(fd, data)
     int fd;
     WAISData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(4, "waisLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	entry->url,
	entry->url,
	"WAIS",
	410,
	"Transaction Timeout",
	"The Network/Remote site may be down or too slow.  Try again later.",
	SQUID_VERSION,
	comm_hostname());
    storeAbort(entry, tmp_error_buf);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    comm_close(fd);
#ifdef LOG_ERRORS
    CacheInfo->log_append(CacheInfo,
	entry->url,
	"0.0.0.0",
	store_mem_obj(entry, e_current_len),
	"ERR_410",		/* WAIS LIFETIME EXPIRE */
	"GET");
#endif
    safe_free(data);
}




/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
void waisReadReply(fd, data)
     int fd;
     WAISData *data;
{
    static char buf[4096];
    int len;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    /* check if we want to defer reading */
	    if ((store_mem_obj(entry, e_current_len) -
		    store_mem_obj(entry, e_lowest_offset)) > WAIS_DELETE_GAP) {
		debug(3, "waisReadReply: Read deferred for Object: %s\n", entry->key);
		debug(3, "                Current Gap: %d bytes\n",
		    store_mem_obj(entry, e_current_len) -
		    store_mem_obj(entry, e_lowest_offset));

		/* reschedule, so it will automatically reactivated when Gap is big enough. */
		comm_set_select_handler(fd, COMM_SELECT_READ, (PF) waisReadReply, (caddr_t) data);
		comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT, (PF) waisReadReplyTimeout,
		    (caddr_t) data, getReadTimeout());
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"WAIS",
		419,
		"No Client",
		"All Clients went away before tranmission is complete and object is too big to cache.",
		SQUID_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
	    comm_close(fd);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_419",	/* WAIS NO CLIENTS, BIG OBJECT */
		"GET");
#endif
	    safe_free(data);
	    return;
	}
    }
    len = read(fd, buf, 4096);
    debug(5, "waisReadReply - fd: %d read len:%d\n", fd, len);

    if (len < 0 || ((len == 0) && (store_mem_obj(entry, e_current_len) == 0))) {
	debug(1, "waisReadReply - error reading errno %d: %s\n",
	    errno, xstrerror());
	if (errno == ECONNRESET) {
	    /* Connection reset by peer */
	    /* consider it as a EOF */
	    entry->expires = cached_curtime;

	    sprintf(tmp_error_buf, "\n<p>Warning: The Remote Server sent RESET at the end of transmission.\n");
	    storeAppend(entry, tmp_error_buf, strlen(tmp_error_buf));
	    storeComplete(entry);
	} else {
	    sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
		entry->url,
		entry->url,
		"WAIS",
		405,
		"Read error",
		"Network/Remote site is down.  Try again later.",
		SQUID_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
	}
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_405",		/* WAIS READ ERROR */
	    "GET");
#endif
	safe_free(data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	entry->expires = cached_curtime;
	storeComplete(entry);
	comm_close(fd);
	safe_free(data);
    } else if (((store_mem_obj(entry, e_current_len) + len) > getWAISMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);

	storeAppend(entry, buf, len);
	comm_set_select_handler(fd, COMM_SELECT_READ, (PF) waisReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT, (PF) waisReadReplyTimeout,
	    (caddr_t) data, getReadTimeout());

    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd, COMM_SELECT_READ, (PF) waisReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT, (PF) waisReadReplyTimeout,
	    (caddr_t) data, getReadTimeout());
    }
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void waisSendComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     WAISData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(5, "waisSendComplete - fd: %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "WAIS",
	    401,
	    "Cannot connect to the original site",
	    "The remote site may be down.",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
	comm_close(fd);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_401",		/* WAIS CONNECT FAILURE */
	    "GET");
#endif
	safe_free(data);
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd, COMM_SELECT_READ, (PF) waisReadReply, (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT, (PF) waisReadReplyTimeout,
	    (caddr_t) data, getReadTimeout());
    }
    safe_free(buf);		/* Allocated by waisSendRequest. */
}

/* This will be called when connect completes. Write request. */
void waisSendRequest(fd, data)
     int fd;
     WAISData *data;
{
#define CR '\015'
#define LF '\012'
    int len = strlen(data->request) + 4;
    char *buf;

    debug(5, "waisSendRequest - fd: %d\n", fd);

    if (data->type)
	len += strlen(data->type);
    if (data->mime_hdr)
	len += strlen(data->mime_hdr);

    buf = (char *) xcalloc(1, len + 1);

    if (data->mime_hdr)
	sprintf(buf, "%s %s %s%c%c", data->type, data->request,
	    data->mime_hdr, CR, LF);
    else
	sprintf(buf, "%s %s%c%c", data->type, data->request, CR, LF);
    debug(6, "waisSendRequest - buf:%s\n", buf);
    icpWrite(fd, buf, len, 30, waisSendComplete, data);
}

int waisStart(unusedfd, url, type, mime_hdr, entry)
     int unusedfd;
     char *url;
     char *type;
     char *mime_hdr;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    WAISData *data = NULL;

    debug(3, "waisStart - url:%s, type:%s\n", url, type);
    debug(4, "            header: %s\n", mime_hdr);

    data = (WAISData *) xcalloc(1, sizeof(WAISData));
    data->entry = entry;

    if (!getWaisRelayHost()) {
	debug(0, "waisStart: Failed because no relay host defined!\n");
	sprintf(tmp_error_buf,
	    CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "WAIS",
	    412,
	    "Configuration error.  No WAIS relay host is defined.",
	    "",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_412",		/* WAIS NO RELAY */
	    "GET");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* Parse url. */
    (void) wais_url_parser(url, data->host, &data->port, data->request);
    data->type = type;
    data->mime_hdr = mime_hdr;

    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(4, "waisStart: Failed because we're out of sockets.\n");
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "WAIS",
	    411,
	    "Cached short of file-descriptors, sorry",
	    "",
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_411",		/* WAIS NO FD'S */
	    "GET");
#endif
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(4, "waisstart: Called without IP entry in ipcache. OR lookup failed.\n");
	comm_close(sock);
	sprintf(tmp_error_buf, CACHED_RETRIEVE_ERROR_MSG,
	    entry->url,
	    entry->url,
	    "WAIS",
	    402,
	    "DNS name lookup failure",
	    dns_error_message,
	    SQUID_VERSION,
	    comm_hostname());
	storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	CacheInfo->log_append(CacheInfo,
	    entry->url,
	    "0.0.0.0",
	    store_mem_obj(entry, e_current_len),
	    "ERR_402",		/* WAIS DNS FAILURE */
	    "GET");
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
		"WAIS",
		401,
		"Cannot connect to the original site",
		"The remote site may be down.",
		SQUID_VERSION,
		comm_hostname());
	    storeAbort(entry, tmp_error_buf);
#ifdef LOG_ERRORS
	    CacheInfo->log_append(CacheInfo,
		entry->url,
		"0.0.0.0",
		store_mem_obj(entry, e_current_len),
		"ERR_401",	/* WAIS CONNECT FAIL */
		"GET");
#endif
	    safe_free(data);
	    return COMM_ERROR;
	} else {
	    debug(5, "waisStart - conn %d EINPROGRESS\n", sock);
	}
    }
    /* Install connection complete handler. */
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) waisLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) waisSendRequest, (caddr_t) data);
    return COMM_OK;
}
#endif
