/* $Id: wais.cc,v 1.17 1996/04/04 01:30:54 wessels Exp $ */

/*
 * DEBUG: Section 24          wais
 */

#include "squid.h"

#define  WAIS_DELETE_GAP  (64*1024)

typedef struct _waisdata {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    int port;
    char *type;
    char *mime_hdr;
    char type_id;
    char request[MAX_URL];
} WAISData;

extern char *dns_error_message;

static void waisCloseAndFree(fd, data)
     int fd;
     WAISData *data;
{
    if (fd > 0)
	comm_close(fd);
    xfree(data);
}


static int wais_url_parser(url, host, port, request)
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
static void waisReadReplyTimeout(fd, data)
     int fd;
     WAISData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(24, 4, "waisReadReplyTimeout: Timeout on %d\n url: %s\n", fd, entry->url);
    cached_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ, 0, 0);
    waisCloseAndFree(fd, data);
}

/* This will be called when socket lifetime is expired. */
void waisLifetimeExpire(fd, data)
     int fd;
     WAISData *data;
{
    StoreEntry *entry = NULL;

    entry = data->entry;
    debug(24, 4, "waisLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    cached_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    comm_set_select_handler(fd, COMM_SELECT_READ | COMM_SELECT_WRITE, 0, 0);
    waisCloseAndFree(fd, data);
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
	    if ((entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset) > WAIS_DELETE_GAP) {
		debug(24, 3, "waisReadReply: Read deferred for Object: %s\n",
		    entry->url);
		debug(24, 3, "                Current Gap: %d bytes\n",
		    entry->mem_obj->e_current_len -
		    entry->mem_obj->e_lowest_offset);
		/* reschedule, so it will automatically reactivated
		 * when Gap is big enough. */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) waisReadReply,
		    (caddr_t) data);
#ifdef INSTALL_READ_TIMEOUT_ABOVE_GAP
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) waisReadReplyTimeout,
		    (caddr_t) data,
		    getReadTimeout());
#else
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (caddr_t) NULL,
		    (time_t) 0);
#endif
		/* dont try reading again for a while */
		comm_set_stall(fd, getStallDelay());
		return;
	    }
	} else {
	    /* we can terminate connection right now */
	    cached_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    waisCloseAndFree(fd, data);
	    return;
	}
    }
    len = read(fd, buf, 4096);
    debug(24, 5, "waisReadReply - fd: %d read len:%d\n", fd, len);

    if (len < 0) {
	debug(24, 1, "waisReadReply: FD %d: read failure: %s.\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) waisReadReply, (caddr_t) data);
	    comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
		(PF) waisReadReplyTimeout, (caddr_t) data, getReadTimeout());
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	    cached_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    waisCloseAndFree(fd, data);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	cached_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	waisCloseAndFree(fd, data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	entry->expires = cached_curtime;
	storeComplete(entry);
	waisCloseAndFree(fd, data);
    } else if (((entry->mem_obj->e_current_len + len) > getWAISMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
    } else {
	storeAppend(entry, buf, len);
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
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
    debug(24, 5, "waisSendComplete - fd: %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	waisCloseAndFree(fd, data);
    } else {
	/* Schedule read reply. */
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) waisReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) waisReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
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

    debug(24, 5, "waisSendRequest - fd: %d\n", fd);

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
    debug(24, 6, "waisSendRequest - buf:%s\n", buf);
    icpWrite(fd, buf, len, 30, waisSendComplete, (caddr_t) data);
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

    debug(24, 3, "waisStart - url:%s, type:%s\n", url, type);
    debug(24, 4, "            header: %s\n", mime_hdr);

    data = (WAISData *) xcalloc(1, sizeof(WAISData));
    data->entry = entry;

    if (!getWaisRelayHost()) {
	debug(24, 0, "waisStart: Failed because no relay host defined!\n");
	cached_error_entry(entry, ERR_NO_RELAY, NULL);
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
	debug(24, 4, "waisStart: Failed because we're out of sockets.\n");
	cached_error_entry(entry, ERR_NO_FDS, xstrerror());
	safe_free(data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(24, 4, "waisstart: Called without IP entry in ipcache. OR lookup failed.\n");
	cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	waisCloseAndFree(sock, data);
	return COMM_ERROR;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port))) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    waisCloseAndFree(sock, data);
	    return COMM_ERROR;
	} else {
	    debug(24, 5, "waisStart - conn %d EINPROGRESS\n", sock);
	}
    }
    /* Install connection complete handler. */
    comm_set_select_handler(sock, COMM_SELECT_LIFETIME,
	(PF) waisLifetimeExpire, (caddr_t) data);
    comm_set_select_handler(sock, COMM_SELECT_WRITE,
	(PF) waisSendRequest, (caddr_t) data);
    if (!BIT_TEST(entry->flag, ENTRY_PRIVATE))
	storeSetPublicKey(entry);	/* Make it public */
    return COMM_OK;
}
