
/*
 * $Id: url.cc,v 1.31 1996/08/30 23:23:36 wessels Exp $
 *
 * DEBUG: section 23    URL Parsing
 * AUTHOR: Duane Wessels
 *
 * SQUID Internet Object Cache  http://www.nlanr.net/Squid/
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

char *RequestMethodStr[] =
{
    "NONE",
    "GET",
    "POST",
    "PUT",
    "HEAD",
    "CONNECT"
};

char *ProtocolStr[] =
{
    "NONE",
    "http",
    "ftp",
    "gopher",
    "wais",
    "cache_object",
    "TOTAL"
};

static int url_acceptable[256];
static char hex[17] = "0123456789abcdef";

/* convert %xx in url string to a character 
 * Allocate a new string and return a pointer to converted string */

char *url_convert_hex(org_url, allocate)
     char *org_url;
     int allocate;
{
    static char code[] = "00";
    char *url = NULL;
    char *s = NULL;
    char *t = NULL;

    url = allocate ? (char *) xstrdup(org_url) : org_url;

    if ((int) strlen(url) < 3 || !strchr(url, '%'))
	return url;

    for (s = t = url; *(s + 2); s++) {
	if (*s == '%') {
	    code[0] = *(++s);
	    code[1] = *(++s);
	    *t++ = (char) strtol(code, NULL, 16);
	} else {
	    *t++ = *s;
	}
    }
    do {
	*t++ = *s;
    } while (*s++);
    return url;
}


/* INIT Acceptable table. 
 * Borrow from libwww2 with Mosaic2.4 Distribution   */
void urlInitialize()
{
    unsigned int i;
    char *good =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_$";
    debug(23, 5, "urlInitialize: Initializing...\n");
    for (i = 0; i < 256; i++)
	url_acceptable[i] = 0;
    for (; *good; good++)
	url_acceptable[(unsigned int) *good] = 1;
}


/* Encode prohibited char in string */
/* return the pointer to new (allocated) string */
char *url_escape(url)
     char *url;
{
    char *p, *q;
    char *tmpline = xcalloc(1, MAX_URL);

    q = tmpline;
    for (p = url; *p; p++) {
	if (url_acceptable[(int) (*p)])
	    *q++ = *p;
	else {
	    *q++ = '%';		/* Means hex coming */
	    *q++ = hex[(int) ((*p) >> 4)];
	    *q++ = hex[(int) ((*p) & 15)];
	}
    }
    *q++ = '\0';
    return tmpline;
}

method_t urlParseMethod(s)
     char *s;
{
    if (strcasecmp(s, "GET") == 0) {
	return METHOD_GET;
    } else if (strcasecmp(s, "POST") == 0) {
	return METHOD_POST;
    } else if (strcasecmp(s, "PUT") == 0) {
	return METHOD_PUT;
    } else if (strcasecmp(s, "HEAD") == 0) {
	return METHOD_HEAD;
    } else if (strcasecmp(s, "CONNECT") == 0) {
	return METHOD_CONNECT;
    }
    return METHOD_NONE;
}


protocol_t urlParseProtocol(s)
     char *s;
{
    if (strncasecmp(s, "http", 4) == 0)
	return PROTO_HTTP;
    if (strncasecmp(s, "ftp", 3) == 0)
	return PROTO_FTP;
#ifndef NO_FTP_FOR_FILE
    if (strncasecmp(s, "file", 4) == 0)
	return PROTO_FTP;
#endif
    if (strncasecmp(s, "gopher", 6) == 0)
	return PROTO_GOPHER;
    if (strncasecmp(s, "wais", 4) == 0)
	return PROTO_WAIS;
    if (strncasecmp(s, "cache_object", 12) == 0)
	return PROTO_CACHEOBJ;
    if (strncasecmp(s, "file", 4) == 0)
	return PROTO_FTP;
    return PROTO_NONE;
}


int urlDefaultPort(p)
     protocol_t p;
{
    switch (p) {
    case PROTO_HTTP:
	return 80;
    case PROTO_FTP:
	return 21;
    case PROTO_GOPHER:
	return 70;
    case PROTO_WAIS:
	return 210;
    case PROTO_CACHEOBJ:
	return CACHE_HTTP_PORT;
    default:
	return 0;
    }
}

request_t *urlParse(method, url)
     method_t method;
     char *url;
{
    LOCAL_ARRAY(char, proto, MAX_URL + 1);
    LOCAL_ARRAY(char, login, MAX_URL + 1);
    LOCAL_ARRAY(char, host, MAX_URL + 1);
    LOCAL_ARRAY(char, urlpath, MAX_URL + 1);
    request_t *request = NULL;
    char *t = NULL;
    int port;
    protocol_t protocol = PROTO_NONE;
    int l;
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';

    if ((l = strlen(url)) > MAX_URL) {
	/* terminate so it doesn't overflow other buffers */
	*(url + (MAX_URL >> 1)) = '\0';
	debug(23, 0, "urlParse: URL too large (%d bytes)\n", l);
	return NULL;
    }
    if (method == METHOD_CONNECT) {
	port = CONNECT_PORT;
	if (sscanf(url, "%[^:]:%d", host, &port) < 1)
	    return NULL;
    } else {
	if (sscanf(url, "%[^:]://%[^/]%s", proto, host, urlpath) < 2)
	    return NULL;
	protocol = urlParseProtocol(proto);
	port = urlDefaultPort(protocol);
	/* Is there any login informaiton? */
	if ((t = strrchr(host, '@'))) {
	    strcpy(login, host);
	    t = strrchr(login, '@');
	    *t = 0;
	    strcpy(host, t + 1);
	}
	if ((t = strrchr(host, ':'))) {
	    *t++ = '\0';
	    if (*t != '\0')
		port = atoi(t);
	}
    }
    for (t = host; *t; t++)
	*t = tolower(*t);
    if (port == 0) {
	debug(23, 0, "urlParse: Invalid port == 0\n");
	return NULL;
    }
    request = get_free_request_t();
    request->method = method;
    request->protocol = protocol;
    strncpy(request->host, host, SQUIDHOSTNAMELEN);
    strncpy(request->login, login, MAX_LOGIN_SZ);
    request->port = port;
    strncpy(request->urlpath, urlpath, MAX_URL);
    return request;
}

char *urlCanonical(request, buf)
     request_t *request;
     char *buf;
{
    LOCAL_ARRAY(char, urlbuf, MAX_URL + 1);
    LOCAL_ARRAY(char, portbuf, 32);
    if (buf == NULL)
	buf = urlbuf;
    switch (request->method) {
    case METHOD_CONNECT:
	sprintf(buf, "%s:%d", request->host, request->port);
	break;
    default:
	portbuf[0] = '\0';
	if (request->port != urlDefaultPort(request->protocol))
	    sprintf(portbuf, ":%d", request->port);
	sprintf(buf, "%s://%s%s%s%s%s",
	    ProtocolStr[request->protocol],
	    request->login,
	    *request->login ? "@" : "",
	    request->host,
	    portbuf,
	    request->urlpath);
	break;
    }
    return buf;
}

request_t *requestLink(request)
     request_t *request;
{
    request->link_count++;
    return request;
}

void requestUnlink(request)
     request_t *request;
{
    if (request == NULL)
	return;
    request->link_count--;
    if (request->link_count)
	return;
    safe_free(request->hierarchy.host);
    put_free_request_t(request);
}

int matchDomainName(domain, host)
     char *domain;
     char *host;
{
    int offset;
    if ((offset = strlen(host) - strlen(domain)) < 0)
	return 0;		/* host too short */
    if (strcasecmp(domain, host + offset) != 0)
	return 0;		/* no match at all */
    if (*domain == '.')
	return 1;
    if (*(host + offset - 1) == '.')
	return 1;
    if (offset == 0)
	return 1;
    return 0;
}

int urlCheckRequest(r)
     request_t *r;
{
    int rc = 0;
    switch (r->protocol) {
    case PROTO_HTTP:
    case PROTO_CACHEOBJ:
	rc = 1;
	break;
    case PROTO_FTP:
    case PROTO_GOPHER:
    case PROTO_WAIS:
	if (r->method == METHOD_GET)
	    rc = 1;
	break;
    default:
	break;
    }
    return rc;
}
