
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

char *ConfigParser::lastToken = NULL;
std::queue<std::string> ConfigParser::undo;

int ConfigParser::RecognizeQuotedValues = true;

void
ConfigParser::destruct()
{
    shutting_down = 1;
    fatalf("Bungled %s line %d: %s",
           cfg_filename, config_lineno, config_input_line);
}

void
ConfigParser::strtokFileUndo()
{
    assert(lastToken);
    undo.push(lastToken);
}

void
ConfigParser::strtokFilePutBack(const char *tok)
{
    assert(tok);
    undo.push(tok);
}

char *
xstrtok(char *str, const char *delimiters)
{
    assert(!str); // we are parsing the configuration file
    // no support unless enabled in the configuration and
    // no support for other delimiters (they may need to be eradicated!)
    return (ConfigParser::RecognizeQuotedValues &&
            strcmp(delimiters, " \t\n\r") == 0) ?
           ConfigParser::NextToken() : ::strtok(str, delimiters);
}

char *
ConfigParser::strtokFile(void)
{
    static int fromFile = 0;
    static FILE *wordFile = NULL;
    LOCAL_ARRAY(char, undoToken, CONFIG_LINE_LIMIT);

    char *t, *fn;
    LOCAL_ARRAY(char, buf, CONFIG_LINE_LIMIT);

    if (!undo.empty()) {
        strncpy(undoToken, undo.front().c_str(), sizeof(undoToken));
        undoToken[sizeof(undoToken) - 1] = '\0';
        undo.pop();
        return lastToken = undoToken;
    }

    if (RecognizeQuotedValues)
        return lastToken = ConfigParser::NextToken();

    lastToken = NULL;
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
                return lastToken = t;
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

    return lastToken = t;
}

/// returns token after stripping any comments
/// must be called in non-quoted context only
char *
ConfigParser::StripComment(char *token)
{
    if (!token)
        return NULL;

    // we are outside the quoted string context
    // assume that anything starting with a '#' is a comment
    if (char *comment = strchr(token, '#')) {
        *comment = '\0'; // remove the comment from this token
        (void)strtok(NULL, ""); // remove the comment from the current line
        if (!*token)
            return NULL; // token was a comment
    }

    return token;
}

void
ConfigParser::ParseQuotedString(char **var, bool *wasQuoted)
{
    if (const char *phrase = NextElement(wasQuoted))
        *var = xstrdup(phrase);
    else
        self_destruct();
}

void
ConfigParser::ParseQuotedString(String *var, bool *wasQuoted)
{
    if (const char *phrase = NextElement(wasQuoted))
        var->reset(phrase);
    else
        self_destruct();
}

char *
ConfigParser::NextElement(bool *wasQuoted)
{
    if (wasQuoted)
        *wasQuoted = false;

    // Get all of the remaining string
    char *token = strtok(NULL, "");
    if (token == NULL)
        return NULL;

    // skip leading whitespace (may skip the entire token that way)
    while (xisspace(*token)) ++token;

    if (*token != '"')
        return StripComment(strtok(token, w_space));

    if (wasQuoted)
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
        debugs(3, DBG_CRITICAL, "missing '\"' at the end of quoted string" );
        self_destruct();
    }
    strtok(s-1, "\""); /*Reset the strtok to point after the "  */
    *s = '\0';

    return (token+1);
}

char *
ConfigParser::NextToken()
{
    return NextElement(NULL);
}

const char *
ConfigParser::QuoteString(const String &var)
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
