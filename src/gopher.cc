/*
 * $Id: gopher.cc,v 1.73 1997/03/04 05:16:30 wessels Exp $
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
} GopherStateData;

static int gopherStateFree _PARAMS((int fd, GopherStateData *));
static void gopher_mime_content _PARAMS((char *buf, const char *name, const char *def));
static void gopherMimeCreate _PARAMS((GopherStateData *));
static int gopher_url_parser(const char *url,
    char *host,
    int *port,
    char *type_id,
    char *request);
static void gopherEndHTML _PARAMS((GopherStateData *));
static void gopherToHTML _PARAMS((GopherStateData *, char *inbuf, int len));
static int gopherReadReplyTimeout _PARAMS((int fd, GopherStateData *));
static void gopherLifetimeExpire _PARAMS((int fd, GopherStateData *));
static void gopherReadReply _PARAMS((int fd, GopherStateData *));
static void gopherSendComplete(int fd,
    char *buf,
    int size,
    int errflag,
    void *data);
static void gopherStartComplete _PARAMS((void *, int));
static void gopherSendRequest _PARAMS((int fd, GopherStateData *));
static GopherStateData *CreateGopherStateData _PARAMS((void));
static void gopherConnectDone _PARAMS((int fd, int status, void *data));

static char def_gopher_bin[] = "www/unknown";
static char def_gopher_text[] = "text/plain";

static int
gopherStateFree(int fd, GopherStateData * gopherState)
{
    if (gopherState == NULL)
	return 1;
    if (gopherState->entry)
	storeUnlockObject(gopherState->entry);
    put_free_4k_page(gopherState->buf);
    xfree(gopherState);
    return 0;
}


/* figure out content type from file extension */
static void
gopher_mime_content(char *buf, const char *name, const char *def)
{
    LOCAL_ARRAY(char, temp, MAX_URL);
    char *ext1 = NULL;
    char *ext2 = NULL;
    const char *str = NULL;
    const ext_table_entry *e = NULL;

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
static void
gopherMimeCreate(GopherStateData * data)
{
    LOCAL_ARRAY(char, tempMIME, MAX_MIME);

    sprintf(tempMIME,
	"HTTP/1.0 200 OK Gatewaying\r\n"
	"Server: Squid/%s\r\n"
	"Date: %s\r\n"
	"MIME-version: 1.0\r\n",
	version_string, mkrfc1123(squid_curtime));

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

    t = sscanf(url, "%[a-zA-Z]://%[^/]/%c%s", proto, hostbuf,
	type_id, request);
    if ((t < 2) || strcasecmp(proto, "gopher")) {
	return -1;
    } else if (t == 2) {
	(*type_id) = GOPHER_DIRECTORY;
	request[0] = '\0';
    } else if (t == 3) {
	request[0] = '\0';
    } else {
	/* convert %xx to char */
	(void) url_convert_hex(request, 0);
    }

    host[0] = '\0';
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = GOPHER_PORT;

    return 0;
}

int
gopherCachable(const char *url)
{
    GopherStateData *data = NULL;
    int cachable = 1;
    /* use as temp data structure to parse gopher URL */
    data = CreateGopherStateData();
    /* parse to see type */
    gopher_url_parser(url,
	data->host,
	&data->port,
	&data->type_id,
	data->request);
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
    gopherStateFree(-1, data);
    return cachable;
}

static void
gopherEndHTML(GopherStateData * data)
{
    LOCAL_ARRAY(char, tmpbuf, TEMP_BUF_SIZE);

    if (!data->data_in) {
	sprintf(tmpbuf, "<HTML><HEAD><TITLE>Server Return Nothing.</TITLE>\n"
	    "</HEAD><BODY><HR><H1>Server Return Nothing.</H1></BODY></HTML>\n");
	storeAppend(data->entry, tmpbuf, strlen(tmpbuf));
	return;
    }
}


/* Convert Gopher to HTML */
/* Borrow part of code from libwww2 came with Mosaic distribution */
static void
gopherToHTML(GopherStateData * data, char *inbuf, int len)
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

    entry = data->entry;

    if (data->conversion == HTML_INDEX_PAGE) {
	sprintf(outbuf, "<HTML><HEAD><TITLE>Gopher Index %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>Gopher Search</H1>\n"
	    "<p>This is a searchable Gopher index. Use the search\n"
	    "function of your browser to enter search terms.\n"
	    "<ISINDEX></BODY></HTML>\n", entry->url, entry->url);
	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	BIT_RESET(entry->flag, DELAY_SENDING);
	data->data_in = 1;

	return;
    }
    if (data->conversion == HTML_CSO_PAGE) {
	sprintf(outbuf, "<HTML><HEAD><TITLE>CSO Search of %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>CSO Search</H1>\n"
	    "<P>A CSO database usually contains a phonebook or\n"
	    "directory.  Use the search function of your browser to enter\n"
	    "search terms.</P><ISINDEX></BODY></HTML>\n",
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
	    strcat(outbuf, "<HTML><HEAD><TITLE>CSO Searchs Result</TITLE></HEAD>\n"
		"<BODY><H1>CSO Searchs Result</H1>\n<PRE>\n");
	else
	    strcat(outbuf, "<HTML><HEAD><TITLE>Gopher Menu</TITLE></HEAD>\n"
		"<BODY><H1>Gopher Menu</H1>\n<PRE>\n");
	data->HTML_header_added = 1;
    }
    while ((pos != NULL) && (pos < inbuf + len)) {

	if (data->len != 0) {
	    /* there is something left from last tx. */
	    xstrncpy(line, data->buf, data->len);
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
		xmemcpy(data->buf + data->len, inbuf, len);
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
		    xmemcpy(data->buf, pos, len - (pos - inbuf));
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
		LOCAL_ARRAY(char, result, MAX_CSO_RESULT);

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
			    sprintf(tmpbuf, "</PRE><HR><H2>%s</H2>\n<PRE>", result);
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

static int
gopherReadReplyTimeout(int fd, GopherStateData * data)
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(10, 4, "GopherReadReplyTimeout: Timeout on %d\n url: %s\n", fd, entry->url);
    squid_error_entry(entry, ERR_READ_TIMEOUT, NULL);
    comm_close(fd);
    return 0;
}

/* This will be called when socket lifetime is expired. */
static void
gopherLifetimeExpire(int fd, GopherStateData * data)
{
    StoreEntry *entry = NULL;
    entry = data->entry;
    debug(10, 4, "gopherLifeTimeExpire: FD %d: '%s'\n", fd, entry->url);
    squid_error_entry(entry, ERR_LIFETIME_EXP, NULL);
    commSetSelect(fd,
	COMM_SELECT_READ | COMM_SELECT_WRITE,
	NULL,
	NULL, 0);
    comm_close(fd);
}


/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
gopherReadReply(int fd, GopherStateData * data)
{
    char *buf = NULL;
    int len;
    int clen;
    int off;
    StoreEntry *entry = NULL;
    int bin;

    entry = data->entry;
    if (entry->flag & DELETE_BEHIND && !storeClientWaiting(entry)) {
	/* we can terminate connection right now */
	squid_error_entry(entry, ERR_NO_CLIENTS_BIG_OBJ, NULL);
	comm_close(fd);
	return;
    }
    /* check if we want to defer reading */
    clen = entry->mem_obj->e_current_len;
    off = storeGetLowestReaderOffset(entry);
    if ((clen - off) > GOPHER_DELETE_GAP) {
	if (entry->flag & CLIENT_ABORT_REQUEST) {
	    squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	    comm_close(fd);
	    return;
	}
	IOStats.Gopher.reads_deferred++;
	debug(10, 3, "gopherReadReply: Read deferred for Object: %s\n",
	    entry->url);
	debug(10, 3, "                Current Gap: %d bytes\n", clen - off);
	/* reschedule, so it will automatically reactivated when
	 * Gap is big enough.  */
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    (PF) gopherReadReply,
	    (void *) data, 0);
	/* don't install read timeout until we are below the GAP */
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    NULL,
	    NULL,
	    0);
	if (!BIT_TEST(entry->flag, READ_DEFERRED)) {
	    comm_set_fd_lifetime(fd, 3600);	/* limit during deferring */
	    BIT_SET(entry->flag, READ_DEFERRED);
	}
	/* dont try reading again for a while */
	comm_set_stall(fd, Config.stallDelay);
	return;
    } else {
	BIT_RESET(entry->flag, READ_DEFERRED);
    }
    buf = get_free_4k_page();
    errno = 0;
    /* leave one space for \0 in gopherToHTML */
    len = read(fd, buf, TEMP_BUF_SIZE - 1);
    debug(10, 5, "gopherReadReply: FD %d read len=%d\n", fd, len);
    if (len > 0) {
	IOStats.Gopher.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Gopher.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1, "gopherReadReply: error reading: %s\n", xstrerror());
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
	    /* reinstall handlers */
	    /* XXX This may loop forever */
	    commSetSelect(fd,
		COMM_SELECT_READ,
		(PF) gopherReadReply,
		(void *) data, 0);
	    commSetSelect(fd,
		COMM_SELECT_TIMEOUT,
		(PF) gopherReadReplyTimeout,
		(void *) data,
		Config.readTimeout);
	} else {
	    BIT_RESET(entry->flag, ENTRY_CACHABLE);
	    storeReleaseRequest(entry);
	    squid_error_entry(entry, ERR_READ_ERROR, xstrerror());
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->e_current_len == 0) {
	squid_error_entry(entry,
	    ERR_ZERO_SIZE_OBJECT,
	    errno ? xstrerror() : NULL);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	/* flush the rest of data in temp buf if there is one. */
	if (data->conversion != NORMAL)
	    gopherEndHTML(data);
	if (!(entry->flag & DELETE_BEHIND))
	    storeTimestampsSet(entry);
	BIT_RESET(entry->flag, DELAY_SENDING);
	storeComplete(entry);
	comm_close(fd);
    } else if (entry->flag & CLIENT_ABORT_REQUEST) {
	/* append the last bit of info we got */
	if (data->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	squid_error_entry(entry, ERR_CLIENT_ABORT, NULL);
	if (data->conversion != NORMAL)
	    gopherEndHTML(data);
	BIT_RESET(entry->flag, DELAY_SENDING);
	comm_close(fd);
    } else {
	if (data->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    (PF) gopherReadReply,
	    (void *) data, 0);
	commSetSelect(fd,
	    COMM_SELECT_TIMEOUT,
	    (PF) gopherReadReplyTimeout,
	    (void *) data,
	    Config.readTimeout);
    }
    put_free_4k_page(buf);
    return;
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
gopherSendComplete(int fd, char *buf, int size, int errflag, void *data)
{
    GopherStateData *gopherState = (GopherStateData *) data;
    StoreEntry *entry = NULL;
    entry = gopherState->entry;
    debug(10, 5, "gopherSendComplete: FD %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (errflag) {
	squid_error_entry(entry, ERR_CONNECT_FAIL, xstrerror());
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

    if (!BIT_TEST(entry->flag, ENTRY_HTML))
	gopherState->conversion = NORMAL;
    else
	switch (gopherState->type_id) {

	case GOPHER_DIRECTORY:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    gopherState->conversion = HTML_DIR;
	    gopherState->HTML_header_added = 0;
	    break;

	case GOPHER_INDEX:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    gopherState->conversion = HTML_INDEX_RESULT;
	    gopherState->HTML_header_added = 0;
	    break;

	case GOPHER_CSO:
	    /* we got to convert it first */
	    BIT_SET(entry->flag, DELAY_SENDING);
	    gopherState->conversion = HTML_CSO_RESULT;
	    gopherState->cso_recno = 0;
	    gopherState->HTML_header_added = 0;
	    break;

	default:
	    gopherState->conversion = NORMAL;

	}
    /* Schedule read reply. */
    commSetSelect(fd,
	COMM_SELECT_READ,
	(PF) gopherReadReply,
	(void *) gopherState, 0);
    commSetSelect(fd,
	COMM_SELECT_TIMEOUT,
	(PF) gopherReadReplyTimeout,
	(void *) gopherState,
	Config.readTimeout);
    comm_set_fd_lifetime(fd, 86400);	/* extend lifetime */

    if (buf)
	put_free_4k_page(buf);	/* Allocated by gopherSendRequest. */
}

/* This will be called when connect completes. Write request. */
static void
gopherSendRequest(int fd, GopherStateData * data)
{
    LOCAL_ARRAY(char, query, MAX_URL);
    char *buf = get_free_4k_page();
    char *t;
    if (data->type_id == GOPHER_CSO) {
	sscanf(data->request, "?%s", query);
	sprintf(buf, "query %s\r\nquit\r\n", query);
    } else if (data->type_id == GOPHER_INDEX) {
	if ((t = strchr(data->request, '?')))
	    *t = '\t';
	sprintf(buf, "%s\r\n", data->request);
    } else {
	sprintf(buf, "%s\r\n", data->request);
    }
    debug(10, 5, "gopherSendRequest: FD %d\n", fd);
    comm_write(fd,
	buf,
	strlen(buf),
	30,
	gopherSendComplete,
	(void *) data,
	put_free_4k_page);
    if (BIT_TEST(data->entry->flag, ENTRY_CACHABLE))
	storeSetPublicKey(data->entry);		/* Make it public */
}

int
gopherStart(StoreEntry * entry)
{
    storeLockObject(entry, gopherStartComplete, entry);
    return COMM_OK;
}


static void
gopherStartComplete(void *datap, int status)
{
    StoreEntry *entry = datap;
    char *url = entry->url;
    GopherStateData *data = CreateGopherStateData();
    int sock;
    data->entry = entry;
    debug(10, 3, "gopherStart: url: %s\n", url);
    /* Parse url. */
    if (gopher_url_parser(url, data->host, &data->port,
	    &data->type_id, data->request)) {
	squid_error_entry(entry, ERR_INVALID_URL, NULL);
	gopherStateFree(-1, data);
	return;
    }
    /* Create socket. */
    sock = comm_open(SOCK_STREAM,
	0,
	Config.Addrs.tcp_outgoing,
	0,
	COMM_NONBLOCKING,
	url);
    if (sock == COMM_ERROR) {
	debug(10, 4, "gopherStart: Failed because we're out of sockets.\n");
	squid_error_entry(entry, ERR_NO_FDS, xstrerror());
	gopherStateFree(-1, data);
	return;
    }
    comm_add_close_handler(sock,
	(PF) gopherStateFree,
	(void *) data);
    /* check if IP is already in cache. It must be. 
     * It should be done before this route is called. 
     * Otherwise, we cannot check return code for connect. */
    if (!ipcache_gethostbyname(data->host, 0)) {
	debug(10, 4, "gopherStart: Called without IP entry in ipcache. OR lookup failed.\n");
	squid_error_entry(entry, ERR_DNS_FAIL, dns_error_message);
	comm_close(sock);
	return;
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
	comm_close(sock);
	return;
    }
    commConnectStart(sock,
	data->host,
	data->port,
	gopherConnectDone,
	data);
}

static void
gopherConnectDone(int fd, int status, void *data)
{
    GopherStateData *gopherState = data;
    if (status == COMM_ERROR) {
	squid_error_entry(gopherState->entry, ERR_CONNECT_FAIL, xstrerror());
	comm_close(fd);
	return;
    }
    /* Install connection complete handler. */
    if (opt_no_ipcache)
	ipcacheInvalidate(gopherState->host);
    commSetSelect(fd,
	COMM_SELECT_LIFETIME,
	(PF) gopherLifetimeExpire,
	(void *) gopherState, 0);
    commSetSelect(fd,
	COMM_SELECT_WRITE,
	(PF) gopherSendRequest,
	(void *) gopherState, 0);
}


static GopherStateData *
CreateGopherStateData(void)
{
    GopherStateData *gd = xcalloc(1, sizeof(GopherStateData));
    gd->buf = get_free_4k_page();
    return (gd);
}
