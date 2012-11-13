
/*
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
 *
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#include "squid.h"
#include "cache_cf.h"
#include "ConfigParser.h"
#include "Debug.h"
#include "fatal.h"
#include "globals.h"

void
ConfigParser::destruct()
{
    shutting_down = 1;
    fatalf("Bungled %s line %d: %s",
           cfg_filename, config_lineno, config_input_line);
}

char *
ConfigParser::strtokFile(void)
{
    static int fromFile = 0;
    static FILE *wordFile = NULL;

    char *t, *fn;
    LOCAL_ARRAY(char, buf, CONFIG_LINE_LIMIT);

    do {

        if (!fromFile) {
            t = (strtok(NULL, w_space));

            if (!t || *t == '#') {
                return NULL;
            } else if (*t == '\"' || *t == '\'') {
                /* quote found, start reading from file */
                fn = ++t;

                while (*t && *t != '\"' && *t != '\'')
                    ++t;

                *t = '\0';

                if ((wordFile = fopen(fn, "r")) == NULL) {
                    debugs(28, DBG_CRITICAL, "strtokFile: " << fn << " not found");
                    return (NULL);
                }

#if _SQUID_WINDOWS_
                setmode(fileno(wordFile), O_TEXT);
#endif

                fromFile = 1;
            } else {
                return t;
            }
        }

        /* fromFile */
        if (fgets(buf, CONFIG_LINE_LIMIT, wordFile) == NULL) {
            /* stop reading from file */
            fclose(wordFile);
            wordFile = NULL;
            fromFile = 0;
            return NULL;
        } else {
            char *t2, *t3;
            t = buf;
            /* skip leading and trailing white space */
            t += strspn(buf, w_space);
            t2 = t + strcspn(t, w_space);
            t3 = t2 + strspn(t2, w_space);

            while (*t3 && *t3 != '#') {
                t2 = t3 + strcspn(t3, w_space);
                t3 = t2 + strspn(t2, w_space);
            }

            *t2 = '\0';
        }

        /* skip comments */
        /* skip blank lines */
    } while ( *t == '#' || !*t );

    return t;
}

void
ConfigParser::ParseQuotedString(char **var, bool *wasQuoted)
{
    String sVar;
    ParseQuotedString(&sVar, wasQuoted);
    *var = xstrdup(sVar.termedBuf());
}

void
ConfigParser::ParseQuotedString(String *var, bool *wasQuoted)
{
    // Get all of the remaining string
    char *token = strtok(NULL, "");
    if (token == NULL)
        self_destruct();

    if (*token != '"') {
        token = strtok(token, w_space);
        var->reset(token);
        if (wasQuoted)
            *wasQuoted = false;
        return;
    } else if (wasQuoted)
        *wasQuoted = true;

    char  *s = token + 1;
    /* scan until the end of the quoted string, unescaping " and \  */
    while (*s && *s != '"') {
        if (*s == '\\') {
            const char * next = s+1; // may point to 0
            memmove(s, next, strlen(next) + 1);
        }
        ++s;
    }

    if (*s != '"') {
        debugs(3, DBG_CRITICAL, "ParseQuotedString: missing '\"' at the end of quoted string" );
        self_destruct();
    }
    strtok(s-1, "\""); /*Reset the strtok to point after the "  */
    *s = '\0';

    var->reset(token+1);
}

const char *
ConfigParser::QuoteString(String &var)
{
    static String quotedStr;
    const char *s = var.termedBuf();
    bool  needQuote = false;

    for (const char *l = s; !needQuote &&  *l != '\0'; ++l  )
        needQuote = !isalnum(*l);

    if (!needQuote)
        return s;

    quotedStr.clean();
    quotedStr.append('"');
    for (; *s != '\0'; ++s) {
        if (*s == '"' || *s == '\\')
            quotedStr.append('\\');
        quotedStr.append(*s);
    }
    quotedStr.append('"');
    return quotedStr.termedBuf();
}
