/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 66    HTTP Header Tools */

#include "squid.h"
#include "base/TextException.h"
#include "sbuf/SBuf.h"
#include "SquidString.h"
#include "StrList.h"

void
strListAdd(String &str, const char *item, const size_t itemSize, const char delimiter)
{
    if (str.size()) {
        const char buf[] = { delimiter, ' ' };
        const auto bufSize = sizeof(buf);
        Must(str.canGrowBy(bufSize));
        str.append(buf, bufSize);
    }
    Must(str.canGrowBy(itemSize));
    str.append(item, itemSize);
}

void
strListAdd(String *str, const char *item, const char delimiter)
{
    assert(str);
    assert(item);
    strListAdd(*str, item, strlen(item), delimiter);
}

void
strListAdd(String &str, const SBuf &item, char delimiter)
{
    strListAdd(str, item.rawContent(), item.length(), delimiter);
}

/** returns true iff "m" is a member of the list */
int
strListIsMember(const String * list, const SBuf &m, char del)
{
    const char *pos = NULL;
    const char *item;
    int ilen = 0;

    assert(list);
    int mlen = m.plength();
    while (strListGetItem(list, del, &item, &ilen, &pos)) {
        if (mlen == ilen && m.caseCmp(item, ilen) == 0)
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
     * implementation is equavalent to strstr()! Thus, we replace the loop with
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

SBuf
getListMember(const String &list, const char *key, const char delimiter)
{
    const char *pos = nullptr;
    const char *item = nullptr;
    int ilen = 0;
    const auto keyLen = strlen(key);
    while (strListGetItem(&list, delimiter, &item, &ilen, &pos)) {
        if (static_cast<size_t>(ilen) > keyLen && strncmp(item, key, keyLen) == 0 && item[keyLen] == '=')
            return SBuf(item + keyLen + 1, ilen - keyLen - 1);
    }
    return SBuf();
}

