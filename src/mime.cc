
/* $Id: mime.cc,v 1.12 1996/04/16 05:05:25 wessels Exp $ */

/*
 * DEBUG: Section 25          mime
 */

#include "squid.h"
#include "mime_table.h"

#define GET_HDR_SZ 1024

char *mime_get_header(char *mime, char *name)
{
    static char header[GET_HDR_SZ];
    char *p = NULL;
    char *q = NULL;
    char got = 0;
    int namelen = strlen(name);

    if (!mime || !name)
	return NULL;

    debug(25, 5, "mime_get_header: looking for '%s'\n", name);

    for (p = mime; *p; p += strcspn(p, "\n\r")) {
	if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
	    return NULL;
	while (isspace(*p))
	    p++;
	if (strncasecmp(p, name, namelen))
	    continue;
	if (!isspace(p[namelen]) && p[namelen] != ':')
	    continue;
	strncpy(header, p, GET_HDR_SZ);
	debug(25, 5, "mime_get_header: checking '%s'\n", header);
	header[GET_HDR_SZ - 1] = 0;
	header[strcspn(header, "\n\r")] = 0;
	q = header;
	q += namelen;
	if (*q == ':')
	    q++, got = 1;
	while (isspace(*q))
	    q++, got = 1;
	if (got) {
	    debug(25, 5, "mime_get_header: returning '%s'\n", q);
	    return q;
	}
    }
    return NULL;
}

int mime_refresh_request(mime)
     char *mime;
{
    char *pr = NULL;
    if (mime == NULL)
	return 0;
    if (mime_get_header(mime, "If-Modified-Since"))
	return 1;
    if ((pr = mime_get_header(mime, "pragma"))) {
	if (strcasecmp(pr, "no-cache"))
	    return 1;
    }
    return 0;
}

ext_table_entry *mime_ext_to_type(extension)
     char *extension;
{
    int i;
    int low;
    int high;
    int comp;
    static char ext[16];
    char *cp = NULL;

    if (!extension || strlen(extension) >= (sizeof(ext) - 1))
	return NULL;
    strcpy(ext, extension);
    for (cp = ext; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);
    low = 0;
    high = EXT_TABLE_LEN - 1;
    while (low <= high) {
	i = (low + high) / 2;
	if ((comp = strcmp(ext, ext_mime_table[i].name)) == 0)
	    return &ext_mime_table[i];
	if (comp > 0)
	    low = i + 1;
	else
	    high = i - 1;
    }
    return NULL;
}

/*
 *  mk_mime_hdr - Generates a MIME header using the given parameters.
 *  You can call mk_mime_hdr with a 'lmt = time(NULL) - ttl' to
 *  generate a fake Last-Modified-Time for the header.
 *  'ttl' is the number of seconds relative to the current time
 *  that the object is valid.
 *
 *  Returns the MIME header in the provided 'result' buffer, and
 *  returns non-zero on error, or 0 on success.
 */
int mk_mime_hdr(result, ttl, size, lmt, type)
     char *result, *type;
     int size;
     time_t ttl, lmt;
{
    time_t expiretime;
    time_t t;
    static char date[100];
    static char expire[100];
    static char last_modified_time[100];

    if (result == NULL)
	return 1;

    t = squid_curtime;
    expiretime = t + ttl;

    date[0] = expire[0] = last_modified_time[0] = result[0] = '\0';
    strncpy(date, mkrfc850(&t), 100);
    strncpy(expire, mkrfc850(&expiretime), 100);
    strncpy(last_modified_time, mkrfc850(&lmt), 100);

    sprintf(result, "Content-Type: %s\r\nContent-Size: %d\r\nDate: %s\r\nExpires: %s\r\nLast-Modified-Time: %s\r\n", type, size, date, expire, last_modified_time);
    return 0;
}
