/* $Id: gopher.cc,v 1.14 1996/04/04 01:30:44 wessels Exp $ */

/*
 * DEBUG: Section 10          gopher: GOPHER
 */

#include "squid.h"

extern char *dns_error_message;

/* gopher type code from rfc. Anawat. */
#define GOPHER_FILE         '0'
#define GOPHER_DIRECTORY    '1'
#define GOPHER_CSO          '2'
#define GOPHER_ERROR        '3'
#define GOPHER_MACBINHEX    '4'
#define GOPHER_DOSBIN       '5'
#define GOPHER_UUENCODED    '6'
#define GOPHER_INDEX        '7'
#define GOPHER_TELNET       '8'
#define GOPHER_BIN          '9'
#define GOPHER_REDUNT       '+'
#define GOPHER_3270         'T'
#define GOPHER_GIF          'g'
#define GOPHER_IMAGE        'I'

#define GOPHER_HTML         'h'	/* HTML */
#define GOPHER_INFO         'i'
#define GOPHER_WWW          'w'	/* W3 address */
#define GOPHER_SOUND        's'

#define GOPHER_PLUS_IMAGE   ':'
#define GOPHER_PLUS_MOVIE   ';'
#define GOPHER_PLUS_SOUND   '<'

#define GOPHER_PORT         70
#define GOPHER_DELETE_GAP   (64*1024)

#define TAB                 '\t'
#define TEMP_BUF_SIZE       SM_PAGE_SIZE
#define MAX_CSO_RESULT      1024

typedef struct gopher_ds {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    enum {
	NORMAL,
	HTML_DIR,
	HTML_INDEX_RESULT,
	HTML_CSO_RESULT,
	HTML_INDEX_PAGE,
	HTML_CSO_PAGE
    } conversion;
    int HTML_header_added;
    int port;
    char type_id;
    char request[MAX_URL];
    int data_in;
    int cso_recno;
    int len;
    char *buf;			/* pts to a 4k page */
    char *icp_page_ptr;		/* Pts to gopherStart buffer that needs to be freed */
    char *icp_rwd_ptr;		/* Pts to icp rw structure that needs to be freed */
} GopherData;

GopherData *CreateGopherData();


char def_gopher_bin[] = "www/unknown";
char def_gopher_text[] = "text/plain";

static void gopherCloseAndFree(fd, data)
     int fd;
     GopherData *data;
{
    if (fd > 0)
	comm_close(fd);
    put_free_4k_page(data->buf);
    xfree(data);
}


/* figure out content type from file extension */
static void gopher_mime_content(buf, name, def)
     char *buf;
     char *name;
     char *def;
{
    static char temp[MAX_URL];
    char *ext1 = NULL;
    char *ext2 = NULL;
    char *str = NULL;
    ext_table_entry *e = NULL;

    ext2 = NULL;
    strcpy(temp, name);
    for (ext1 = temp; *ext1; ext1++)
	if (isupper(*ext1))
	    *ext1 = tolower(*ext1);
    if ((ext1 = strrchr(temp, '.')) == NULL) {
	/* use default */
	sprintf(buf + strlen(buf), "Content-Type: %s\r\n", def);
	return;
    }
    /* try extension table */
    *ext1++ = 0;
    if (strcmp("gz", ext1) == 0 || strcmp("z", ext1) == 0) {
	ext2 = ext1;
	if ((ext1 = strrchr(temp, '.')) == NULL) {
	    ext1 = ext2;
	    ext2 = NULL;
	} else
	    ext1++;
    }
    if ((e = mime_ext_to_type(ext1)) == NULL) {
	/* mime_ext_to_type() can return a NULL */
	if (ext2 && (e = mime_ext_to_type(ext2))) {
	    str = e->mime_type;
	    ext2 = NULL;
	} else {
	    str = def;
	}
    } else {
	str = e->mime_type;
    }
    sprintf(buf + strlen(buf), "Content-Type: %s\r\n", str);
    if (ext2 && (e = mime_ext_to_type(ext2))) {
	sprintf(buf + strlen(buf), "Content-Encoding: %s\r\n",
	    e->mime_encoding);
    }
}



/* create MIME Header for Gopher Data */
void gopherMimeCreate(data)
     GopherData *data;
{
    static char tempMIME[MAX_MIME];

    sprintf(tempMIME, "\
HTTP/1.0 200 OK Gatewaying\r\n\
Server: HarvestCache/%s\r\n\
MIME-version: 1.0\r\n", SQUID_VERSION);

    switch (data->type_id) {

    case GOPHER_DIRECTORY:
    case GOPHER_INDEX:
    case GOPHER_HTML:
    case GOPHER_WWW:
    case GOPHER_CSO:
	strcat(tempMIME, "Content-Type: text/html\r\n");
	break;
    case GOPHER_GIF:
    case GOPHER_IMAGE:
    case GOPHER_PLUS_IMAGE:
	strcat(tempMIME, "Content-Type: image/gif\r\n");
	break;
    case GOPHER_SOUND:
    case GOPHER_PLUS_SOUND:
	strcat(tempMIME, "Content-Type: audio/basic\r\n");
	break;
    case GOPHER_PLUS_MOVIE:
	strcat(tempMIME, "Content-Type: video/mpeg\r\n");
	break;
    case GOPHER_MACBINHEX:
    case GOPHER_DOSBIN:
    case GOPHER_UUENCODED:
    case GOPHER_BIN:
	/* Rightnow We have no idea what it is. */
	gopher_mime_content(tempMIME, data->request, def_gopher_bin);
	break;

    case GOPHER_FILE:
    default:
	gopher_mime_content(tempMIME, data->request, def_gopher_text);
	break;

    }

    strcat(tempMIME, "\r\n");
    storeAppend(data->entry, tempMIME, strlen(tempMIME));
}

/* Parse a gopher url into components.  By Anawat. */
int gopher_url_parser(url, host, port, type_id, request)
     char *url;
     char *host;
     int *port;
     char *type_id;
     char *request;
{
    static char atypebuf[MAX_URL];
    static char hostbuf[MAX_URL];
    char *tmp = NULL;
    int t;

    atypebuf[0] = hostbuf[0] = '\0';
    host[0] = request[0] = '\0';
    (*port) = 0;
    (*type_id) = 0;

    t = sscanf(url, "%[a-zA-Z]://%[^/]/%c%s", atypebuf, hostbuf,
	type_id, request);
    if ((t < 2) || strcasecmp(atypebuf, "gopher")) {
	return -1;
    } else if (t == 2) {
	(*type_id) = GOPHER_DIRECTORY;
	request[0] = '\0';
    } else if (t == 3) {
	request[0] = '\0';
    } else {
	/* convert %xx to char */
	tmp = url_convert_hex(request);
	strncpy(request, tmp, MAX_URL);
	safe_free(tmp);
    }

    host[0] = '\0';
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = GOPHER_PORT;

    return 0;
}

int gopherCachable(url)
     char *url;
{
    stoplist *p = NULL;
    GopherData *data = NULL;
    int cachable = 1;

    /* scan stop list */
    for (p = gopher_stoplist; p; p = p->next)
	if (strstr(url, p->key))
	    return 0;

    /* use as temp data structure to parse gopher URL */
    data = CreateGopherData();

    /* parse to see type */
    gopher_url_parser(url, data->host, &data->port, &data->type_id, data->request);

    switch (data->type_id) {
    case GOPHER_INDEX:
    case GOPHER_CSO:
    case GOPHER_TELNET:
    case GOPHER_3270:
	cachable = 0;
	break;
    default:
	cachable = 1;
    }
    gopherCloseAndFree(-1, data);

    return cachable;
}

void gopherEndHTML(data)
     GopherData *data;
{
    static char tmpbuf[TEMP_BUF_SIZE];

    if (!data->data_in) {
	sprintf(tmpbuf, "<HR><H2><i>Server Return Nothing.</i></H2>\n");
	storeAppend(data->entry, tmpbuf, strlen(tmpbuf));
	return;
    }
}


/* Convert Gopher to HTML */
/* Borrow part of code from libwww2 came with Mosaic distribution */
void gopherToHTML(data, inbuf, len)
     GopherData *data;
     char *inbuf;
     int len;
{
    char *pos = inbuf;
    char *lpos = NULL;
    char *tline = NULL;
    static char line[TEMP_BUF_SIZE];
    static char tmpbuf[TEMP_BUF_SIZE];
    static char outbuf[TEMP_BUF_SIZE << 4];
    char *name = NULL;
    char *selector = NULL;
    char *host = NULL;
    char *port = NULL;
    char *escaped_selector = NULL;
    char *icon_type = NULL;
    char gtype;
    StoreEntry *entry = NULL;

    memset(outbuf, '\0', sizeof(outbuf));
    memset(tmpbuf, '\0', sizeof(outbuf));
    memset(line, '\0', sizeof(outbuf));

    entry = data->entry;

    if (data->conversion == HTML_INDEX_PAGE) {
	sprintf(outbuf, "<TITLE>Gopher Index %s</TITLE><H1>%s<BR>Gopher Search</H1> This is a searchable Gopher index.Use the search function of your browser to enter search terms. <ISINDEX>\n", entry->url, entry->url);

	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	BIT_RESET(entry->flag, DELAY_SENDING);
	data->data_in = 1;

	return;
    }
    if (data->conversion == HTML_CSO_PAGE) {
	sprintf(outbuf, "<TITLE>CSO Search of %s</TITLE><H1>%s<BR>CSO Search</H1>A CSO database usually contains a phonebook or directory. Use the search function of your browser to enter search terms.<ISINDEX>\n",
	    entry->url, entry->url);

	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	BIT_RESET(entry->flag, DELAY_SENDING);
	data->data_in = 1;

	return;
    }
    inbuf[len] = '\0';

    if (!data->HTML_header_added) {
	if (data->conversion == HTML_CSO_RESULT)
	    strcat(outbuf, "<H1>CSO Searchs Result</H1>\n<PRE>\n");
	else
	    strcat(outbuf, "<H1>Gopher Menu</H1>\n<PRE>\n");
	data->HTML_header_added = 1;
    }
    while ((pos != NULL) && (pos < inbuf + len)) {

	if (data->len != 0) {
	    /* there is something left from last tx. */
	    strncpy(line, data->buf, data->len);
	    lpos = (char *) memccpy(line + data->len, inbuf, '\n', len);
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if (data->len + len > TEMP_BUF_SIZE) {
		    debug(10, 1, "GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			entry->url);
		    len = TEMP_BUF_SIZE - data->len;
		}
		memcpy(data->buf + data->len, inbuf, len);
		data->len += len;
		return;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', 256);
	    if (pos)
		pos++;

	    /* we're done with the remain from last tx. */
	    data->len = 0;
	    *(data->buf) = '\0';
	} else {

	    lpos = (char *) memccpy(line, pos, '\n', len - (pos - inbuf));
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if ((len - (pos - inbuf)) > TEMP_BUF_SIZE) {
		    debug(10, 1, "GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			entry->url);
		    len = TEMP_BUF_SIZE;
		}
		if (len > (pos - inbuf)) {
		    memcpy(data->buf, pos, len - (pos - inbuf));
		    data->len = len - (pos - inbuf);
		}
		break;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', 256);
	    if (pos)
		pos++;

	}

	/* at this point. We should have one line in buffer to process */

	if (*line == '.') {
	    /* skip it */
	    memset(line, '\0', TEMP_BUF_SIZE);
	    continue;
	}
	switch (data->conversion) {

	case HTML_INDEX_RESULT:
	case HTML_DIR:{
		tline = line;
		gtype = *tline++;
		name = tline;
		selector = strchr(tline, TAB);
		if (selector) {
		    *selector++ = '\0';
		    host = strchr(selector, TAB);
		    if (host) {
			*host++ = '\0';
			port = strchr(host, TAB);
			if (port) {
			    char *junk;
			    port[0] = ':';
			    junk = strchr(host, TAB);
			    if (junk)
				*junk++ = 0;	/* Chop port */
			    else {
				junk = strchr(host, '\r');
				if (junk)
				    *junk++ = 0;	/* Chop port */
				else {
				    junk = strchr(host, '\n');
				    if (junk)
					*junk++ = 0;	/* Chop port */
				}
			    }
			    if ((port[1] == '0') && (!port[2]))
				port[0] = 0;	/* 0 means none */
			}
			/* escape a selector here */
			escaped_selector = url_escape(selector);

			switch (gtype) {
			case GOPHER_DIRECTORY:
			    icon_type = "internal-gopher-menu";
			    break;
			case GOPHER_FILE:
			    icon_type = "internal-gopher-text";
			    break;
			case GOPHER_INDEX:
			case GOPHER_CSO:
			    icon_type = "internal-gopher-index";
			    break;
			case GOPHER_IMAGE:
			case GOPHER_GIF:
			case GOPHER_PLUS_IMAGE:
			    icon_type = "internal-gopher-image";
			    break;
			case GOPHER_SOUND:
			case GOPHER_PLUS_SOUND:
			    icon_type = "internal-gopher-sound";
			    break;
			case GOPHER_PLUS_MOVIE:
			    icon_type = "internal-gopher-movie";
			    break;
			case GOPHER_TELNET:
			case GOPHER_3270:
			    icon_type = "internal-gopher-telnet";
			    break;
			case GOPHER_BIN:
			case GOPHER_MACBINHEX:
			case GOPHER_DOSBIN:
			case GOPHER_UUENCODED:
			    icon_type = "internal-gopher-binary";
			    break;
			default:
			    icon_type = "internal-gopher-unknown";
			    break;
			}


			memset(tmpbuf, '\0', TEMP_BUF_SIZE);
			if ((gtype == GOPHER_TELNET) || (gtype == GOPHER_3270)) {
			    if (strlen(escaped_selector) != 0)
				sprintf(tmpbuf, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s@%s/\">%s</A>\n",
				    icon_type, escaped_selector, host, name);
			    else
				sprintf(tmpbuf, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s/\">%s</A>\n",
				    icon_type, host, name);

			} else {
			    sprintf(tmpbuf, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"gopher://%s/%c%s\">%s</A>\n",
				icon_type, host, gtype, escaped_selector, name);
			}
			safe_free(escaped_selector);
			strcat(outbuf, tmpbuf);
			data->data_in = 1;
		    } else {
			memset(line, '\0', TEMP_BUF_SIZE);
			continue;
		    }
		} else {
		    memset(line, '\0', TEMP_BUF_SIZE);
		    continue;
		}
		break;
	    }			/* HTML_DIR, HTML_INDEX_RESULT */


	case HTML_CSO_RESULT:{
		int t;
		int code;
		int recno;
		char result[MAX_CSO_RESULT];

		tline = line;

		if (tline[0] == '-') {
		    t = sscanf(tline, "-%d:%d:%[^\n]", &code, &recno, result);
		    if (t < 3)
			break;

		    if (code != 200)
			break;

		    if (data->cso_recno != recno) {
			sprintf(tmpbuf, "</PRE><HR><H2>Record# %d<br><i>%s</i></H2>\n<PRE>", recno, result);
			data->cso_recno = recno;
		    } else {
			sprintf(tmpbuf, "%s\n", result);
		    }
		    strcat(outbuf, tmpbuf);
		    data->data_in = 1;
		    break;
		} else {
		    /* handle some error codes */
		    t = sscanf(tline, "%d:%[^\n]", &code, result);

		    if (t < 2)
			break;

		    switch (code) {

		    case 200:{
			    /* OK */
			    /* Do nothing here */
			    break;
			}

		    case 102:	/* Number of matches */
		    case 501:	/* No Match */
		    case 502:	/* Too Many Matches */
			{
			    /* Print the message the server returns */
			    sprintf(tmpbuf, "</PRE><HR><H2><i>%s</i></H2>\n<PRE>", result);
			    strcat(outbuf, tmpbuf);
			    data->data_in = 1;
			    break;
			}


		    }
		}

	    }			/* HTML_CSO_RESULT */
	default:
	    break;		/* do nothing */

	}			/* switch */

    }				/* while loop */

    if ((int) strlen(outbuf) > 0) {
	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	BIT_RESET(entry->flag, DELAY_SENDING);
    }
    return;
}


int gopherReadReplyTimeout(fd, data)
     int fd;
     GopherData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(10, 4, "GopherReadReplyTimeout: Timeout on %d\n url: %s\n", fd, entry->url);
    cached_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    if (data->icp_page_ptr)
	put_free_4k_page(data->icp_page_ptr);
    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    gopherCloseAndFree(fd, data);
    return 0;
}

/* This will be called when socket lifetime is expired. */
void gopherLifetimeExpire(fd, data)
     int fd;
     GopherData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(10, 4, "gopherLifeTimeExpire: FD %d: <URL:%s>\n", fd, entry->url);
    cached_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    if (data->icp_page_ptr)
	put_free_4k_page(data->icp_page_ptr);
    if (data->icp_rwd_ptr)
	safe_free(data->icp_rwd_ptr);
    comm_set_select_handler(fd,
	COMM_SELECT_READ | COMM_SELECT_WRITE,
	0,
	0);
    gopherCloseAndFree(fd, data);
}




/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
int gopherReadReply(fd, data)
     int fd;
     GopherData *data;
{
    char *buf = NULL;
    int len;
    int clen;
    int off;
    StoreEntry *entry = NULL;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND) {
	if (storeClientWaiting(entry)) {
	    clen = entry->mem_obj->e_current_len;
	    off = entry->mem_obj->e_lowest_offset;
	    if ((clen - off) > GOPHER_DELETE_GAP) {
		debug(10, 3, "gopherReadReply: Read deferred for Object: %s\n",
		    entry->url);
		debug(10, 3, "                Current Gap: %d bytes\n",
		    clen - off);

		/* reschedule, so it will automatically reactivated when
		 * Gap is big enough.  */
		comm_set_select_handler(fd,
		    COMM_SELECT_READ,
		    (PF) gopherReadReply,
		    (caddr_t) data);
/* don't install read timeout until we are below the GAP */
#ifdef INSTALL_READ_TIMEOUT_ABOVE_GAP
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) gopherReadReplyTimeout,
		    (caddr_t) data,
		    getReadTimeout());
#else
		comm_set_select_handler_plus_timeout(fd,
		    COMM_SELECT_TIMEOUT,
		    (PF) NULL,
		    (caddr_t) NULL,
		    (time_t) 0);
#endif
		comm_set_stall(fd, getStallDelay());	/* dont try reading again for a while */
		return 0;
	    }
	} else {
	    /* we can terminate connection right now */
	    cached_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	    gopherCloseAndFree(fd, data);
	    return 0;
	}
    }
    buf = get_free_4k_page();
    errno = 0;
    len = read(fd, buf, TEMP_BUF_SIZE - 1);	/* leave one space for \0 in gopherToHTML */
    debug(10, 5, "gopherReadReply: FD %d read len=%d\n", fd, len);

    if (len < 0) {
	debug(10, 1, "gopherReadReply: error reading: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    comm_set_select_handler(fd, COMM_SELECT_READ,
		(PF) gopherReadReply, (caddr_t) data);
	    comm_set_select_handler_plus_timeout(fd, COMM_SELECT_TIMEOUT,
		(PF) gopherReadReplyTimeout, (caddr_t) data, getReadTimeout());
	} else {
	    BIT_RESET(entry->flag, CACHABLE);
	    BIT_SET(entry->flag, RELEASE_REQUEST);
	    cached_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    gopherCloseAndFree(fd, data);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	cached_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	gopherCloseAndFree(fd, data);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	/* flush the rest of data in temp buf if there is one. */
	if (data->conversion != NORMAL)
	    gopherEndHTML(data);
	if (!(entry->flag & DELETE_BEHIND))
	    entry->expires = cached_curtime + ttlSet(entry);
	BIT_RESET(entry->flag, DELAY_SENDING);
	storeComplete(entry);
	gopherCloseAndFree(fd, data);
    } else if (((entry->mem_obj->e_current_len + len) > getGopherMax()) &&
	!(entry->flag & DELETE_BEHIND)) {
	/*  accept data, but start to delete behind it */
	storeStartDeleteBehind(entry);

	if (data->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) gopherReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) gopherReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we got */
	if (data->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	cached_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	if (data->conversion != NORMAL)
	    gopherEndHTML(data);
	BIT_RESET(entry->flag, DELAY_SENDING);
	gopherCloseAndFree(fd, data);
    } else {
	if (data->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	comm_set_select_handler(fd,
	    COMM_SELECT_READ,
	    (PF) gopherReadReply,
	    (caddr_t) data);
	comm_set_select_handler_plus_timeout(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) gopherReadReplyTimeout,
	    (caddr_t) data,
	    getReadTimeout());
    }
    put_free_4k_page(buf);
    return 0;
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
void gopherSendComplete(fd, buf, size, errflag, data)
     int fd;
     char *buf;
     int size;
     int errflag;
     GopherData *data;
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(10, 5, "gopherSendComplete: FD %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	gopherCloseAndFree(fd, data);
	if (buf)
	    put_free_4k_page(buf);	/* Allocated by gopherSendRequest. */
	return;
    }
    /* 
     * OK. We successfully reach remote site.  Start MIME typing
     * stuff.  Do it anyway even though request is not HTML type.
     */
    gopherMimeCreate(data);

    if (!BIT_TEST(entry->flag, ENTRY_HTML))
	data->conversion = NORMAL;
    else
	switch (data->type_id) {

	case GOPHER_DIRECTORY:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    data->conversion = HTML_DIR;
	    data->HTML_header_added = 0;
	    break;

	case GOPHER_INDEX:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    data->conversion = HTML_INDEX_RESULT;
	    data->HTML_header_added = 0;
	    break;

	case GOPHER_CSO:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    data->conversion = HTML_CSO_RESULT;
	    data->cso_recno = 0;
	    data->HTML_header_added = 0;
	    break;

	default:
	    data->conversion = NORMAL;

	}
    /* Schedule read reply. */
    comm_set_select_handler(fd,
	COMM_SELECT_READ,
	(PF) gopherReadReply,
	(caddr_t) data);
    comm_set_select_handler_plus_timeout(fd,
	COMM_SELECT_TIMEOUT,
	(PF) gopherReadReplyTimeout,
	(caddr_t) data,
	getReadTimeout());
    comm_set_fd_lifetime(fd, -1);	/* disable */

    if (buf)
	put_free_4k_page(buf);	/* Allocated by gopherSendRequest. */
    data->icp_page_ptr = NULL;
    data->icp_rwd_ptr = NULL;
}

/* This will be called when connect completes. Write request. */
int gopherSendRequest(fd, data)
     int fd;
     GopherData *data;
{
#define CR '\015'
#define LF '\012'
    int len;
    static char query[MAX_URL];
    char *buf = get_free_4k_page();

    data->icp_page_ptr = buf;

    if (data->type_id == GOPHER_CSO) {
	sscanf(data->request, "?%s", query);
	len = strlen(query) + 15;
	sprintf(buf, "query %s%c%cquit%c%c", query, CR, LF, CR, LF);
    } else if (data->type_id == GOPHER_INDEX) {
	char *c_ptr = strchr(data->request, '?');
	if (c_ptr) {
	    *c_ptr = '\t';
	}
	len = strlen(data->request) + 3;
	sprintf(buf, "%s%c%c", data->request, CR, LF);
    } else {
	len = strlen(data->request) + 3;
	sprintf(buf, "%s%c%c", data->request, CR, LF);
    }

    debug(10, 5, "gopherSendRequest: FD %d\n", fd);
    data->icp_rwd_ptr = icpWrite(fd,
	buf,
	len,
	30,
	gopherSendComplete,
	(caddr_t) data);
    return 0;
}

int gopherStart(unusedfd, url, entry)
     int unusedfd;
     char *url;
     StoreEntry *entry;
{
    /* Create state structure. */
    int sock, status;
    GopherData *data = CreateGopherData();

    data->entry = entry;

    debug(10, 3, "gopherStart: url: %s\n", url);

    /* Parse url. */
    if (gopher_url_parser(url, data->host, &data->port,
	    &data->type_id, data->request)) {
	cached_error_entry(entry, ERR_INVALID_URL, NULL);
	gopherCloseAndFree(-1, data);
	return COMM_ERROR;
    }
    /* Create socket. */
    sock = comm_open(COMM_NONBLOCKING, 0, 0, url);
    if (sock == COMM_ERROR) {
	debug(10, 4, "gopherStart: Failed because we're out of sockets.\n");
	cached_error_entry(entry, ERR_NO_FDS, xstrerror());
	gopherCloseAndFree(-1, data);
	return COMM_ERROR;
    }
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host)) {
	debug(10, 4, "gopherStart: Called without IP entry in ipcache. OR lookup failed.\n");
	cached_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	gopherCloseAndFree(sock, data);
	return COMM_ERROR;
    }
    if (((data->type_id == GOPHER_INDEX) || (data->type_id == GOPHER_CSO))
	&& (strchr(data->request, '?') == NULL)
	&& (BIT_TEST(entry->flag, ENTRY_HTML))) {
	/* Index URL without query word */
	/* We have to generate search page back to client. No need for connection */
	gopherMimeCreate(data);

	if (data->type_id == GOPHER_INDEX) {
	    data->conversion = HTML_INDEX_PAGE;
	} else {
	    if (data->type_id == GOPHER_CSO) {
		data->conversion = HTML_CSO_PAGE;
	    } else {
		data->conversion = HTML_INDEX_PAGE;
	    }
	}
	gopherToHTML(data, (char *) NULL, 0);
	storeComplete(entry);
	gopherCloseAndFree(sock, data);
	return COMM_OK;
    }
    /* Open connection. */
    if ((status = comm_connect(sock, data->host, data->port)) != 0) {
	if (status != EINPROGRESS) {
	    cached_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
	    gopherCloseAndFree(sock, data);
	    return COMM_ERROR;
	} else {
	    debug(10, 5, "startGopher: conn %d EINPROGRESS\n", sock);
	}
    }
    /* Install connection complete handler. */
    comm_set_select_handler(sock,
	COMM_SELECT_LIFETIME,
	(PF) gopherLifetimeExpire,
	(caddr_t) data);
    comm_set_select_handler(sock,
	COMM_SELECT_WRITE,
	(PF) gopherSendRequest,
	(caddr_t) data);
    if (!BIT_TEST(entry->flag, ENTRY_PRIVATE))
	storeSetPublicKey(entry);	/* Make it public */

    return COMM_OK;
}


GopherData *CreateGopherData()
{
    GopherData *gd = (GopherData *) xcalloc(1, sizeof(GopherData));
    gd->buf = get_free_4k_page();
    return (gd);
}
