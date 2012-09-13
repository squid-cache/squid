/*
 * DEBUG: section 66    HTTP Header Tools
 * AUTHOR: Alex Rousskov
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "SquidString.h"
#include "StrList.h"

/** appends an item to the list */
void
strListAdd(String * str, const char *item, char del)
{
    assert(str && item);
    if (str->size()) {
        char buf[3];
        buf[0] = del;
        buf[1] = ' ';
        buf[2] = '\0';
        str->append(buf, 2);
    }
    str->append(item, strlen(item));
}

/** returns true iff "m" is a member of the list */
int
strListIsMember(const String * list, const char *m, char del)
{
    const char *pos = NULL;
    const char *item;
    int ilen = 0;
    int mlen;

    assert(list && m);
    mlen = strlen(m);
    while (strListGetItem(list, del, &item, &ilen, &pos)) {
        if (mlen == ilen && !strncasecmp(item, m, ilen))
            return 1;
    }
    return 0;
}

/** returns true iff "s" is a substring of a member of the list */
int
strListIsSubstr(const String * list, const char *s, char del)
{
    assert(list && del);
    return (list->find(s) != String::npos);

    /** \note
     * Note: the original code with a loop is broken because it uses strstr()
     * instead of strnstr(). If 's' contains a 'del', strListIsSubstr() may
     * return true when it should not. If 's' does not contain a 'del', the
     * implementaion is equavalent to strstr()! Thus, we replace the loop with
     * strstr() above until strnstr() is available.
     */
}

/**
 * iterates through a 0-terminated string of items separated by 'del's.
 * white space around 'del' is considered to be a part of 'del'
 * like strtok, but preserves the source, and can iterate several strings at once
 *
 * returns true if next item is found.
 * init pos with NULL to start iteration.
 */
int
strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos)
{
    size_t len;
    /* ',' is always enabled as field delimiter as this is required for
     * processing merged header values properly, even if Cookie normally
     * uses ';' as delimiter.
     */
    static char delim[3][8] = {
        "\"?,",
        "\"\\",
        " ?,\t\r\n"
    };
    int quoted = 0;
    assert(str && item && pos);

    delim[0][1] = del;
    delim[2][1] = del;

    if (!*pos) {
        *pos = str->termedBuf();

        if (!*pos)
            return 0;
    }

    /* skip leading whitespace and delimiters */
    *pos += strspn(*pos, delim[2]);

    *item = *pos;       /* remember item's start */

    /* find next delimiter */
    do {
        *pos += strcspn(*pos, delim[quoted]);
        if (**pos == '"') {
            quoted = !quoted;
            *pos += 1;
        } else if (quoted && **pos == '\\') {
            *pos += 1;
            if (**pos)
                *pos += 1;
        } else {
            break;      /* Delimiter found, marking the end of this value */
        }
    } while (**pos);

    len = *pos - *item;     /* *pos points to del or '\0' */

    /* rtrim */
    while (len > 0 && xisspace((*item)[len - 1]))
        --len;

    if (ilen)
        *ilen = len;

    return len > 0;
}

