/* $Id: url.cc,v 1.12 1996/04/12 04:53:53 wessels Exp $ */

/* 
 * DEBUG: Section 23          url
 */

#include "squid.h"


static int url_acceptable[256];
static int url_acceptable_init = 0;
static char hex[17] = "0123456789abcdef";

/* convert %xx in url string to a character 
 * Allocate a new string and return a pointer to converted string */

char *url_convert_hex(org_url, allocate)
     char *org_url;
     int allocate;
{
    static char *code = "00";
    char *url = NULL;
    char *s = NULL;
    char *t = NULL;

    url = allocate ? (char *) xstrdup(org_url) : org_url;

    if (strlen(url) < 3 || !strchr(url, '%'))
	return url;

    for (s = t = url; *(s + 2); s++) {
	if (*s == '%') {
	    *code = *++s;
	    *(code + 1) = *++s;
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
static void init_url_acceptable()
{
    unsigned int i;
    char *good =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_$";
    for (i = 0; i < 256; i++)
	url_acceptable[i] = 0;
    for (; *good; good++)
	url_acceptable[(unsigned int) *good] = 1;
    url_acceptable_init = 1;
}


/* Encode prohibited char in string */
/* return the pointer to new (allocated) string */
char *url_escape(url)
     char *url;
{
    char *p, *q;
    char *tmpline = xcalloc(1, MAX_URL);

    if (!url_acceptable_init)
	init_url_acceptable();

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


#ifdef NOT_YET_USED
/*
 * Strip the url from e->key, return a pointer to a static copy of it.
 * Planning ahead for removing e->url from meta-data
 */
char *the_url(e)
     StoreEntry *e;
{
    char *URL;
    char *token;
    static char line_in[MAX_URL + 1];
    static char delim[] = "/";
    int i;

    strcpy(line_in, e->key);
    token = strtok(line_in, delim);

    if (!(e->flag & CACHABLE) && (sscanf(token, "%d", &i))) {
	URL = strtok(NULL, "~");	/* Non_CACHABLE, key = /%d/url */
	return URL;
    }
    if ((e->flag & KEY_CHANGE) && (sscanf(token, "x%d", &i))) {
	/* key is changed, key = /x%d/url or /x%d/head/url or /x%d/post/url */
	/* Now key is url or head/url or post/url */
	token = strtok(NULL, "~");
    } else {
	/* key is url or /head/url or /post/url */
	strcpy(token, e->key);
    }

    if (e->method == METHOD_GET) {
	/* key is url */
	return token;
    } else if ((e->method == METHOD_POST) &&
	(!(strncmp(token, "post/", 5)) || !(strncmp(token, "/post/", 6)))) {
	URL = strtok(token, delim);
	URL = strtok(NULL, "~");
	/* discard "/post/" or "post/" from the key and get url */
	return URL;
    } else if ((e->method == METHOD_HEAD) &&
	(!(strncmp(token, "head/", 5)) || !(strncmp(token, "/head/", 6)))) {
	URL = strtok(token, delim);
	URL = strtok(NULL, "~");
	/* discard "/head/" or "head/" from the key and get url */
	return URL;
    } else {
	debug(23, 0, "Should not be here. Unknown format of the key: %s\n",
	    e->key);
	return (NULL);
    }
}
#endif

char *RequestMethodStr[] =
{
    "NONE",
    "GET",
    "POST",
    "HEAD"
};

char *ProtocolStr[] =
{
    "NONE",
    "http",
    "ftp",
    "wais",
    "cache_object",
    "TOTAL"
};

method_t urlParseMethod(s)
     char *s;
{
    if (strcasecmp(s, "GET") == 0) {
	return METHOD_GET;
    } else if (strcasecmp(s, "POST") == 0) {
	return METHOD_POST;
    } else if (strcasecmp(s, "HEAD") == 0) {
	return METHOD_HEAD;
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
    if (strncasecmp(s, "gopher", 6) == 0)
	return PROTO_GOPHER;
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
    case PROTO_CACHEOBJ:
	return CACHE_HTTP_PORT;
    default:
	return 0;
    }
}
