/*
 * $Id: mime.cc,v 1.39 1997/10/16 19:22:39 kostas Exp $
 *
 * DEBUG: section 25    MIME Parsing
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

#define GET_HDR_SZ 1024

typedef struct _mime_entry {
    char *pattern;
    regex_t compiled_pattern;
    char *icon;
    char *content_type;
    char *content_encoding;
    char transfer_mode;
    struct _mime_entry *next;
} mimeEntry;

static mimeEntry *MimeTable = NULL;
static mimeEntry **MimeTableTail = NULL;

static void mimeLoadIconFile _PARAMS((const char *icon));

char *
mime_get_header(const char *mime, const char *name)
{
    LOCAL_ARRAY(char, header, GET_HDR_SZ);
    const char *p = NULL;
    char *q = NULL;
    char got = 0;
    int namelen = strlen(name);
    int l;

    if (!mime || !name)
	return NULL;

    debug(25, 5) ("mime_get_header: looking for '%s'\n", name);

    for (p = mime; *p; p += strcspn(p, "\n\r")) {
	if (strcmp(p, "\r\n\r\n") == 0 || strcmp(p, "\n\n") == 0)
	    return NULL;
	while (isspace(*p))
	    p++;
	if (strncasecmp(p, name, namelen))
	    continue;
	if (!isspace(p[namelen]) && p[namelen] != ':')
	    continue;
	l = strcspn(p, "\n\r") + 1;
	if (l > GET_HDR_SZ)
	    l = GET_HDR_SZ;
	xstrncpy(header, p, l);
	debug(25, 5) ("mime_get_header: checking '%s'\n", header);
	q = header;
	q += namelen;
	if (*q == ':')
	    q++, got = 1;
	while (isspace(*q))
	    q++, got = 1;
	if (got) {
	    debug(25, 5) ("mime_get_header: returning '%s'\n", q);
	    return q;
	}
    }
    return NULL;
}

/* need to take the lowest, non-zero pointer to the end of the headers.
 * The headers end at the first empty line */
char *
mime_headers_end(const char *mime)
{
    const char *p1, *p2;
    const char *end = NULL;

    p1 = strstr(mime, "\n\r\n");
    p2 = strstr(mime, "\n\n");

    if (p1 && p2)
	end = p1 < p2 ? p1 : p2;
    else
	end = p1 ? p1 : p2;
    if (end)
	end += (end == p1 ? 3 : 2);

    return (char *) end;
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
int
mk_mime_hdr(char *result, const char *type, int size, time_t ttl, time_t lmt)
{
    time_t expiretime;
    time_t t;
    LOCAL_ARRAY(char, date, 100);
    LOCAL_ARRAY(char, expires, 100);
    LOCAL_ARRAY(char, last_modified, 100);
    LOCAL_ARRAY(char, content_length, 100);

    if (result == NULL)
	return 1;
    t = squid_curtime;
    expiretime = ttl ? t + ttl : 0;
    date[0] = expires[0] = last_modified[0] = '\0';
    content_length[0] = result[0] = '\0';
    snprintf(date,100, "Date: %s\r\n", mkrfc1123(t));
    if (ttl >= 0)
	snprintf(expires, 100, "Expires: %s\r\n", mkrfc1123(expiretime));
    if (lmt)
	snprintf(last_modified,100, "Last-Modified: %s\r\n", mkrfc1123(lmt));
    if (size > 0)
	snprintf(content_length,100, "Content-Length: %d\r\n", size);

	/* NOTE: don't know size of result thus didn't change
	   to snprintf(). Should be done sometime! */

    snprintf(result, MAX_MIME, "Server: %s/%s\r\n%s%s%sContent-Type: %s\r\n%s",
	appname,
	version_string,
	date,
	expires,
	last_modified,
	type,
	content_length);
    return 0;
}


char *
mimeGetIcon(const char *fn)
{
    mimeEntry *m;
    for (m = MimeTable; m; m = m->next) {
	if (m->icon == NULL)
	    continue;
	if (regexec(&m->compiled_pattern, fn, 0, 0, 0) == 0)
	    break;
    }
    if (m == NULL)
	return NULL;
    if (!strcmp(m->icon, dash_str))
	return NULL;
    return m->icon;
}

char *
mimeGetContentType(const char *fn)
{
    mimeEntry *m;
    char *name = xstrdup(fn);
    char *t;
    if (mimeGetContentEncoding(name)) {
	/* Assume we matched /\.\w$/ and cut off the last extension */
	if ((t = strrchr(name, '.')))
	    *t = '\0';
    }
    for (m = MimeTable; m; m = m->next) {
	if (m->content_type == NULL)
	    continue;
	if (regexec(&m->compiled_pattern, name, 0, 0, 0) == 0)
	    break;
    }
    xfree(name);
    if (m == NULL)
	return NULL;
    if (!strcmp(m->content_type, dash_str))
	return NULL;
    return m->content_type;
}

char *
mimeGetContentEncoding(const char *fn)
{
    mimeEntry *m;
    for (m = MimeTable; m; m = m->next) {
	if (m->content_encoding == NULL)
	    continue;
	if (regexec(&m->compiled_pattern, fn, 0, 0, 0) == 0)
	    break;
    }
    if (m == NULL)
	return NULL;
    if (!strcmp(m->content_encoding, dash_str))
	return NULL;
    return m->content_encoding;
}

char
mimeGetTransferMode(const char *fn)
{
    mimeEntry *m;
    for (m = MimeTable; m; m = m->next) {
	if (regexec(&m->compiled_pattern, fn, 0, 0, 0) == 0)
	    break;
    }
    return m ? m->transfer_mode : 'I';
}

void
mimeInit(char *filename)
{
    FILE *fp;
    char buf[BUFSIZ];
    char chopbuf[BUFSIZ];
    char *t;
    char *pattern;
    char *icon;
    char *type;
    char *encoding;
    char *mode;
    regex_t re;
    mimeEntry *m;
    int re_flags = REG_EXTENDED | REG_NOSUB | REG_ICASE;
    if (filename == NULL)
	return;
    if ((fp = fopen(filename, "r")) == NULL) {
	debug(50, 1) ("mimeInit: %s: %s\n", filename, xstrerror());
	return;
    }
    if (MimeTableTail == NULL)
	MimeTableTail = &MimeTable;
    while (fgets(buf, BUFSIZ, fp)) {
	if ((t = strchr(buf, '#')))
	    *t = '\0';
	if ((t = strchr(buf, '\r')))
	    *t = '\0';
	if ((t = strchr(buf, '\n')))
	    *t = '\0';
	if (buf[0] == '\0')
	    continue;
	xstrncpy(chopbuf, buf, BUFSIZ);
	if ((pattern = strtok(chopbuf, w_space)) == NULL) {
	    debug(25, 1) ("mimeInit: parse error: '%s'\n", buf);
	    continue;
	}
	if ((type = strtok(NULL, w_space)) == NULL) {
	    debug(25, 1) ("mimeInit: parse error: '%s'\n", buf);
	    continue;
	}
	if ((icon = strtok(NULL, w_space)) == NULL) {
	    debug(25, 1) ("mimeInit: parse error: '%s'\n", buf);
	    continue;
	}
	if ((encoding = strtok(NULL, w_space)) == NULL) {
	    debug(25, 1) ("mimeInit: parse error: '%s'\n", buf);
	    continue;
	}
	if ((mode = strtok(NULL, w_space)) == NULL) {
	    debug(25, 1) ("mimeInit: parse error: '%s'\n", buf);
	    continue;
	}
	if (regcomp(&re, pattern, re_flags) != 0) {
	    debug(25, 1) ("mimeInit: regcomp error: '%s'\n", buf);
	    continue;
	}
	m = xcalloc(1, sizeof(mimeEntry));
	m->pattern = xstrdup(pattern);
	m->content_type = xstrdup(type);
	m->icon = xstrdup(icon);
	m->content_encoding = xstrdup(encoding);
	m->compiled_pattern = re;
	if (!strcasecmp(mode, "ascii"))
	    m->transfer_mode = 'A';
	else if (!strcasecmp(mode, "text"))
	    m->transfer_mode = 'A';
	else
	    m->transfer_mode = 'I';
	mimeLoadIconFile(m->icon);
	debug(25, 5) ("mimeInit: added '%s'\n", buf);
	*MimeTableTail = m;
	MimeTableTail = &m->next;
    }
    fclose(fp);
    mimeLoadIconFile(ICON_MENU);
    mimeLoadIconFile(ICON_DIRUP);
    mimeLoadIconFile(ICON_LINK);
    debug(25, 1) ("Loaded Icons.\n");
}

static void
mimeLoadIconFile(const char *icon)
{
    int fd;
    int n;
    int l;
    struct stat sb;
    StoreEntry *e;
    LOCAL_ARRAY(char, path, MAXPATHLEN);
    LOCAL_ARRAY(char, url, MAX_URL);
    char *buf;
    snprintf(url, MAX_URL, "http://internal.squid/icons/%s", icon);
    if (storeGet(url))
	return;
    snprintf(path, MAXPATHLEN, "%s/%s", Config.icons.directory, icon);
    fd = file_open(path, O_RDONLY, NULL, NULL);
    if (fd < 0) {
	debug(25, 0) ("mimeLoadIconFile: %s: %s\n", path, xstrerror());
	return;
    }
    if (fstat(fd, &sb) < 0) {
	debug(50, 0) ("mimeLoadIconFile: FD %d: fstat: %s\n", fd, xstrerror());
	return;
    }
    e = storeCreateEntry(url,
	url,
	REQ_CACHABLE,
	METHOD_GET);
    assert(e != NULL);
    e->mem_obj->request = requestLink(urlParse(METHOD_GET, url));
    buf = get_free_4k_page();
    l = 0;
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "HTTP/1.0 200 OK\r\n");
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Date: %s\r\n", mkrfc1123(squid_curtime));
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Server: Squid/%s\r\n", version_string);
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Content-Type: %s\r\n", Config.icons.content_type);
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Content-Length: %d\r\n", (int) sb.st_size);
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Last-Modified: %s\r\n", mkrfc1123(sb.st_mtime));
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "Expires: %s\r\n", mkrfc1123(squid_curtime + 86400));
    l += snprintf(buf + l, SM_PAGE_SIZE - l, "\r\n");
    httpParseReplyHeaders(buf, e->mem_obj->reply);
    storeAppend(e, buf, l);
    while ((n = read(fd, buf, SM_PAGE_SIZE)) > 0)
	storeAppend(e, buf, n);
    file_close(fd);
    storeSetPublicKey(e);
    storeComplete(e);
    storeTimestampsSet(e);
    BIT_SET(e->flag, ENTRY_SPECIAL);
    debug(25, 3) ("Loaded icon %s\n", url);
    storeUnlockObject(e);
    put_free_4k_page(buf);
}
