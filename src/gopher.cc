
/*
 * $Id: gopher.cc,v 1.117 1998/01/05 21:44:42 wessels Exp $
 *
 * DEBUG: section 10    Gopher
 * AUTHOR: Harvest Derived
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

/*
 * Copyright (c) 1994, 1995.  All rights reserved.
 *  
 *   The Harvest software was developed by the Internet Research Task
 *   Force Research Group on Resource Discovery (IRTF-RD):
 *  
 *         Mic Bowman of Transarc Corporation.
 *         Peter Danzig of the University of Southern California.
 *         Darren R. Hardy of the University of Colorado at Boulder.
 *         Udi Manber of the University of Arizona.
 *         Michael F. Schwartz of the University of Colorado at Boulder.
 *         Duane Wessels of the University of Colorado at Boulder.
 *  
 *   This copyright notice applies to software in the Harvest
 *   ``src/'' directory only.  Users should consult the individual
 *   copyright notices in the ``components/'' subdirectories for
 *   copyright information about other software bundled with the
 *   Harvest source code distribution.
 *  
 * TERMS OF USE
 *   
 *   The Harvest software may be used and re-distributed without
 *   charge, provided that the software origin and research team are
 *   cited in any use of the system.  Most commonly this is
 *   accomplished by including a link to the Harvest Home Page
 *   (http://harvest.cs.colorado.edu/) from the query page of any
 *   Broker you deploy, as well as in the query result pages.  These
 *   links are generated automatically by the standard Broker
 *   software distribution.
 *   
 *   The Harvest software is provided ``as is'', without express or
 *   implied warranty, and with no support nor obligation to assist
 *   in its use, correction, modification or enhancement.  We assume
 *   no liability with respect to the infringement of copyrights,
 *   trade secrets, or any patents, and are not responsible for
 *   consequential damages.  Proper use of the Harvest software is
 *   entirely the responsibility of the user.
 *  
 * DERIVATIVE WORKS
 *  
 *   Users may make derivative works from the Harvest software, subject 
 *   to the following constraints:
 *  
 *     - You must include the above copyright notice and these 
 *       accompanying paragraphs in all forms of derivative works, 
 *       and any documentation and other materials related to such 
 *       distribution and use acknowledge that the software was 
 *       developed at the above institutions.
 *  
 *     - You must notify IRTF-RD regarding your distribution of 
 *       the derivative work.
 *  
 *     - You must clearly notify users that your are distributing 
 *       a modified version and not the original Harvest software.
 *  
 *     - Any derivative product is also subject to these copyright 
 *       and use restrictions.
 *  
 *   Note that the Harvest software is NOT in the public domain.  We
 *   retain copyright, as specified above.
 *  
 * HISTORY OF FREE SOFTWARE STATUS
 *  
 *   Originally we required sites to license the software in cases
 *   where they were going to build commercial products/services
 *   around Harvest.  In June 1995 we changed this policy.  We now
 *   allow people to use the core Harvest software (the code found in
 *   the Harvest ``src/'' directory) for free.  We made this change
 *   in the interest of encouraging the widest possible deployment of
 *   the technology.  The Harvest software is really a reference
 *   implementation of a set of protocols and formats, some of which
 *   we intend to standardize.  We encourage commercial
 *   re-implementations of code complying to this set of standards.  
 */

#include "squid.h"

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
    int fd;
} GopherStateData;

static PF gopherStateFree;
static void gopher_mime_content(char *buf, const char *name, const char *def);
static void gopherMimeCreate(GopherStateData *);
static int gopher_url_parser(const char *url,
    char *host,
    int *port,
    char *type_id,
    char *request);
static void gopherEndHTML(GopherStateData *);
static void gopherToHTML(GopherStateData *, char *inbuf, int len);
static PF gopherTimeout;
static PF gopherReadReply;
static CWCB gopherSendComplete;
static PF gopherSendRequest;
static GopherStateData *CreateGopherStateData(void);
static CNCB gopherConnectDone;
static STABH gopherAbort;

static char def_gopher_bin[] = "www/unknown";
static char def_gopher_text[] = "text/plain";

static void
gopherStateFree(int fdnotused, void *data)
{
    GopherStateData *gopherState = data;
    if (gopherState == NULL)
	return;
    if (gopherState->entry) {
	storeUnregisterAbort(gopherState->entry);
	storeUnlockObject(gopherState->entry);
    }
    put_free_4k_page(gopherState->buf);
    gopherState->buf = NULL;
    cbdataFree(gopherState);
}


/* figure out content type from file extension */
static void
gopher_mime_content(char *buf, const char *name, const char *def_ctype)
{
    char *ctype = mimeGetContentType(name);
    char *cenc = mimeGetContentEncoding(name);
    if (cenc)
	snprintf(buf + strlen(buf), MAX_MIME - strlen(buf), "Content-Encoding: %s\r\n", cenc);
    snprintf(buf + strlen(buf), MAX_MIME - strlen(buf), "Content-Type: %s\r\n",
	ctype ? ctype : def_ctype);
}



/* create MIME Header for Gopher Data */
static void
gopherMimeCreate(GopherStateData * gopherState)
{
    LOCAL_ARRAY(char, tempMIME, MAX_MIME);

    snprintf(tempMIME, MAX_MIME,
	"HTTP/1.0 200 OK Gatewaying\r\n"
	"Server: Squid/%s\r\n"
	"Date: %s\r\n"
	"MIME-version: 1.0\r\n",
	version_string, mkrfc1123(squid_curtime));

    switch (gopherState->type_id) {

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
	gopher_mime_content(tempMIME, gopherState->request, def_gopher_bin);
	break;
    case GOPHER_FILE:
    default:
	gopher_mime_content(tempMIME, gopherState->request, def_gopher_text);
	break;
    }
    strcat(tempMIME, "\r\n");
    storeAppend(gopherState->entry, tempMIME, strlen(tempMIME));
}

/* Parse a gopher url into components.  By Anawat. */
static int
gopher_url_parser(const char *url, char *host, int *port, char *type_id, char *request)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, hostbuf, MAX_URL);
    int t;

    proto[0] = hostbuf[0] = '\0';
    host[0] = request[0] = '\0';
    (*port) = 0;
    (*type_id) = 0;

    t = sscanf(url,
#if defined(__QNX__)
	"%[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]://%[^/]/%c%s",
#else
	"%[a-zA-Z]://%[^/]/%c%s",
#endif
	proto, hostbuf, type_id, request);
    if ((t < 2) || strcasecmp(proto, "gopher")) {
	return -1;
    } else if (t == 2) {
	(*type_id) = GOPHER_DIRECTORY;
	request[0] = '\0';
    } else if (t == 3) {
	request[0] = '\0';
    } else {
	/* convert %xx to char */
	url_convert_hex(request, 0);
    }

    host[0] = '\0';
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = GOPHER_PORT;

    return 0;
}

int
gopherCachable(const char *url)
{
    GopherStateData *gopherState = NULL;
    int cachable = 1;
    /* use as temp data structure to parse gopher URL */
    gopherState = CreateGopherStateData();
    /* parse to see type */
    gopher_url_parser(url,
	gopherState->host,
	&gopherState->port,
	&gopherState->type_id,
	gopherState->request);
    switch (gopherState->type_id) {
    case GOPHER_INDEX:
    case GOPHER_CSO:
    case GOPHER_TELNET:
    case GOPHER_3270:
	cachable = 0;
	break;
    default:
	cachable = 1;
    }
    gopherStateFree(-1, gopherState);
    return cachable;
}

static void
gopherEndHTML(GopherStateData * gopherState)
{
    LOCAL_ARRAY(char, tmpbuf, TEMP_BUF_SIZE);

    if (!gopherState->data_in) {
	snprintf(tmpbuf, TEMP_BUF_SIZE,
	    "<HTML><HEAD><TITLE>Server Return Nothing.</TITLE>\n"
	    "</HEAD><BODY><HR><H1>Server Return Nothing.</H1></BODY></HTML>\n");
	storeAppend(gopherState->entry, tmpbuf, strlen(tmpbuf));
	return;
    }
}


/* Convert Gopher to HTML */
/* Borrow part of code from libwww2 came with Mosaic distribution */
static void
gopherToHTML(GopherStateData * gopherState, char *inbuf, int len)
{
    char *pos = inbuf;
    char *lpos = NULL;
    char *tline = NULL;
    LOCAL_ARRAY(char, line, TEMP_BUF_SIZE);
    LOCAL_ARRAY(char, tmpbuf, TEMP_BUF_SIZE);
    LOCAL_ARRAY(char, outbuf, TEMP_BUF_SIZE << 4);
    char *name = NULL;
    char *selector = NULL;
    char *host = NULL;
    char *port = NULL;
    char *escaped_selector = NULL;
    char *icon_type = NULL;
    char gtype;
    StoreEntry *entry = NULL;

    memset(outbuf, '\0', TEMP_BUF_SIZE << 4);
    memset(tmpbuf, '\0', TEMP_BUF_SIZE);
    memset(line, '\0', TEMP_BUF_SIZE);

    entry = gopherState->entry;

    if (gopherState->conversion == HTML_INDEX_PAGE) {
	snprintf(outbuf, TEMP_BUF_SIZE << 4,
	    "<HTML><HEAD><TITLE>Gopher Index %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>Gopher Search</H1>\n"
	    "<p>This is a searchable Gopher index. Use the search\n"
	    "function of your browser to enter search terms.\n"
	    "<ISINDEX></BODY></HTML>\n", storeUrl(entry), storeUrl(entry));
	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	storeBufferFlush(entry);
	gopherState->data_in = 1;

	return;
    }
    if (gopherState->conversion == HTML_CSO_PAGE) {
	snprintf(outbuf, TEMP_BUF_SIZE << 4,
	    "<HTML><HEAD><TITLE>CSO Search of %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>CSO Search</H1>\n"
	    "<P>A CSO database usually contains a phonebook or\n"
	    "directory.  Use the search function of your browser to enter\n"
	    "search terms.</P><ISINDEX></BODY></HTML>\n",
	    storeUrl(entry), storeUrl(entry));

	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	storeBufferFlush(entry);
	gopherState->data_in = 1;

	return;
    }
    inbuf[len] = '\0';

    if (!gopherState->HTML_header_added) {
	if (gopherState->conversion == HTML_CSO_RESULT)
	    strcat(outbuf, "<HTML><HEAD><TITLE>CSO Searchs Result</TITLE></HEAD>\n"
		"<BODY><H1>CSO Searchs Result</H1>\n<PRE>\n");
	else
	    strcat(outbuf, "<HTML><HEAD><TITLE>Gopher Menu</TITLE></HEAD>\n"
		"<BODY><H1>Gopher Menu</H1>\n<PRE>\n");
	gopherState->HTML_header_added = 1;
    }
    while ((pos != NULL) && (pos < inbuf + len)) {

	if (gopherState->len != 0) {
	    /* there is something left from last tx. */
	    xstrncpy(line, gopherState->buf, gopherState->len);
	    lpos = (char *) memccpy(line + gopherState->len, inbuf, '\n', len);
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if (gopherState->len + len > TEMP_BUF_SIZE) {
		    debug(10, 1) ("GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			storeUrl(entry));
		    len = TEMP_BUF_SIZE - gopherState->len;
		}
		xmemcpy(gopherState->buf + gopherState->len, inbuf, len);
		gopherState->len += len;
		return;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', len);
	    if (pos)
		pos++;

	    /* we're done with the remain from last tx. */
	    gopherState->len = 0;
	    *(gopherState->buf) = '\0';
	} else {

	    lpos = (char *) memccpy(line, pos, '\n', len - (pos - inbuf));
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if ((len - (pos - inbuf)) > TEMP_BUF_SIZE) {
		    debug(10, 1) ("GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			storeUrl(entry));
		    len = TEMP_BUF_SIZE;
		}
		if (len > (pos - inbuf)) {
		    xmemcpy(gopherState->buf, pos, len - (pos - inbuf));
		    gopherState->len = len - (pos - inbuf);
		}
		break;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', len);
	    if (pos)
		pos++;

	}

	/* at this point. We should have one line in buffer to process */

	if (*line == '.') {
	    /* skip it */
	    memset(line, '\0', TEMP_BUF_SIZE);
	    continue;
	}
	switch (gopherState->conversion) {

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
				snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s@%s/\">%s</A>\n",
				    icon_type, escaped_selector, host, name);
			    else
				snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s/\">%s</A>\n",
				    icon_type, host, name);

			} else {
			    snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"gopher://%s/%c%s\">%s</A>\n",
				icon_type, host, gtype, escaped_selector, name);
			}
			safe_free(escaped_selector);
			strcat(outbuf, tmpbuf);
			gopherState->data_in = 1;
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
		LOCAL_ARRAY(char, result, MAX_CSO_RESULT);

		tline = line;

		if (tline[0] == '-') {
		    t = sscanf(tline, "-%d:%d:%[^\n]", &code, &recno, result);
		    if (t < 3)
			break;

		    if (code != 200)
			break;

		    if (gopherState->cso_recno != recno) {
			snprintf(tmpbuf, TEMP_BUF_SIZE, "</PRE><HR><H2>Record# %d<br><i>%s</i></H2>\n<PRE>", recno, result);
			gopherState->cso_recno = recno;
		    } else {
			snprintf(tmpbuf, TEMP_BUF_SIZE, "%s\n", result);
		    }
		    strcat(outbuf, tmpbuf);
		    gopherState->data_in = 1;
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
			    snprintf(tmpbuf, TEMP_BUF_SIZE, "</PRE><HR><H2>%s</H2>\n<PRE>", result);
			    strcat(outbuf, tmpbuf);
			    gopherState->data_in = 1;
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
	storeBufferFlush(entry);
    }
    return;
}

static void
gopherTimeout(int fd, void *data)
{
    GopherStateData *gopherState = data;
    StoreEntry *entry = gopherState->entry;
    ErrorState *err;
    debug(10, 4) ("gopherTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    if (entry->mem_obj->inmem_hi == 0) {
	err = errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT);
	err->url = xstrdup(gopherState->request);
	errorAppendEntry(entry, err);
    } else {
	storeAbort(entry, 0);
    }
    comm_close(fd);
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
gopherReadReply(int fd, void *data)
{
    GopherStateData *gopherState = data;
    StoreEntry *entry = gopherState->entry;
    char *buf = NULL;
    int len;
    int clen;
    int bin;
    if (protoAbortFetch(entry)) {
	storeAbort(entry, 0);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->inmem_hi;
    buf = get_free_4k_page();
    errno = 0;
    /* leave one space for \0 in gopherToHTML */
    len = read(fd, buf, TEMP_BUF_SIZE - 1);
    fd_bytes(fd, len, FD_READ);
    debug(10, 5) ("gopherReadReply: FD %d read len=%d\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Gopher.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Gopher.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1) ("gopherReadReply: error reading: %s\n", xstrerror());
	if (ignoreErrno(errno)) {
	    commSetSelect(fd, COMM_SELECT_READ, gopherReadReply, data, 0);
	} else if (entry->mem_obj->inmem_hi == 0) {
	    ErrorState *err;
	    err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	    err->xerrno = errno;
	    err->url = xstrdup(storeUrl(entry));
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	} else {
	    storeAbort(entry, 0);
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	ErrorState *err;
	err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->url = xstrdup(gopherState->request);
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	/* flush the rest of data in temp buf if there is one. */
	if (gopherState->conversion != NORMAL)
	    gopherEndHTML(data);
	storeTimestampsSet(entry);
	storeBufferFlush(entry);
	storeComplete(entry);
	comm_close(fd);
    } else {
	if (gopherState->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    gopherReadReply,
	    data, 0);
    }
    put_free_4k_page(buf);
    return;
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
gopherSendComplete(int fd, char *buf, size_t size, int errflag, void *data)
{
    GopherStateData *gopherState = (GopherStateData *) data;
    StoreEntry *entry = gopherState->entry;
    debug(10, 5) ("gopherSendComplete: FD %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	ErrorState *err;
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(gopherState->host);
	err->port = gopherState->port;
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	comm_close(fd);
	if (buf)
	    put_free_4k_page(buf);	/* Allocated by gopherSendRequest. */
	return;
    }
    /* 
     * OK. We successfully reach remote site.  Start MIME typing
     * stuff.  Do it anyway even though request is not HTML type.
     */
    gopherMimeCreate(gopherState);
    switch (gopherState->type_id) {
    case GOPHER_DIRECTORY:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_DIR;
	gopherState->HTML_header_added = 0;
	break;
    case GOPHER_INDEX:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_INDEX_RESULT;
	gopherState->HTML_header_added = 0;
	break;
    case GOPHER_CSO:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_CSO_RESULT;
	gopherState->cso_recno = 0;
	gopherState->HTML_header_added = 0;
	break;
    default:
	gopherState->conversion = NORMAL;
    }
    /* Schedule read reply. */
    commSetSelect(fd, COMM_SELECT_READ, gopherReadReply, gopherState, 0);
    commSetDefer(fd, protoCheckDeferRead, entry);
    if (buf)
	put_free_4k_page(buf);	/* Allocated by gopherSendRequest. */
}

/* This will be called when connect completes. Write request. */
static void
gopherSendRequest(int fd, void *data)
{
    GopherStateData *gopherState = data;
    LOCAL_ARRAY(char, query, MAX_URL);
    char *buf = get_free_4k_page();
    char *t;
    if (gopherState->type_id == GOPHER_CSO) {
	sscanf(gopherState->request, "?%s", query);
	snprintf(buf, 4096, "query %s\r\nquit\r\n", query);
    } else if (gopherState->type_id == GOPHER_INDEX) {
	if ((t = strchr(gopherState->request, '?')))
	    *t = '\t';
	snprintf(buf, 4096, "%s\r\n", gopherState->request);
    } else {
	snprintf(buf, 4096, "%s\r\n", gopherState->request);
    }
    debug(10, 5) ("gopherSendRequest: FD %d\n", fd);
    comm_write(fd,
	buf,
	strlen(buf),
	gopherSendComplete,
	data,
	put_free_4k_page);
    if (EBIT_TEST(gopherState->entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(gopherState->entry);	/* Make it public */
}

void
gopherStart(StoreEntry * entry)
{
    GopherStateData *gopherState = CreateGopherStateData();
    ErrorState *err;
    int fd;
    storeLockObject(entry);
    gopherState->entry = entry;
    debug(10, 3) ("gopherStart: %s\n", storeUrl(entry));
    /* Parse url. */
    if (gopher_url_parser(storeUrl(entry), gopherState->host, &gopherState->port,
	    &gopherState->type_id, gopherState->request)) {
	ErrorState *err;
	err = errorCon(ERR_INVALID_URL, HTTP_BAD_REQUEST);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	gopherStateFree(-1, gopherState);
	return;
    }
    /* Create socket. */
    fd = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	storeUrl(entry));
    if (fd == COMM_ERROR) {
	debug(10, 4) ("gopherStart: Failed because we're out of sockets.\n");
	err = errorCon(ERR_SOCKET_FAILURE, HTTP_INTERNAL_SERVER_ERROR);
	err->xerrno = errno;
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	gopherStateFree(-1, gopherState);
	return;
    }
    comm_add_close_handler(fd, gopherStateFree, gopherState);
    storeRegisterAbort(entry, gopherAbort, gopherState);
    if (((gopherState->type_id == GOPHER_INDEX) || (gopherState->type_id == GOPHER_CSO))
	&& (strchr(gopherState->request, '?') == NULL)) {
	/* Index URL without query word */
	/* We have to generate search page back to client. No need for connection */
	gopherMimeCreate(gopherState);
	if (gopherState->type_id == GOPHER_INDEX) {
	    gopherState->conversion = HTML_INDEX_PAGE;
	} else {
	    if (gopherState->type_id == GOPHER_CSO) {
		gopherState->conversion = HTML_CSO_PAGE;
	    } else {
		gopherState->conversion = HTML_INDEX_PAGE;
	    }
	}
	gopherToHTML(gopherState, (char *) NULL, 0);
	storeComplete(entry);
	comm_close(fd);
	return;
    }
    commSetTimeout(fd, Config.Timeout.connect, gopherTimeout, gopherState);
    commConnectStart(fd,
	gopherState->host,
	gopherState->port,
	gopherConnectDone,
	gopherState);
    gopherState->fd = fd;
}

static void
gopherConnectDone(int fd, int status, void *data)
{
    GopherStateData *gopherState = data;
    StoreEntry *entry = gopherState->entry;

    ErrorState *err;
    if (status == COMM_ERR_DNS) {
	debug(10, 4) ("gopherConnectDone: Unknown host: %s\n", gopherState->host);
	err = errorCon(ERR_DNS_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->dnsserver_msg = xstrdup(dns_error_message);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else if (status != COMM_OK) {
	ErrorState *err;
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(gopherState->host);
	err->port = gopherState->port;
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else {
	commSetSelect(fd, COMM_SELECT_WRITE, gopherSendRequest, gopherState, 0);
    }
}


static GopherStateData *
CreateGopherStateData(void)
{
    GopherStateData *gd = xcalloc(1, sizeof(GopherStateData));
    cbdataAdd(gd);
    gd->buf = get_free_4k_page();
    return (gd);
}

static void
gopherAbort(void *data)
{
    GopherStateData *gopherState = data;
    debug(10, 1) ("gopherAbort: %s\n", storeUrl(gopherState->entry));
    comm_close(gopherState->fd);
}
