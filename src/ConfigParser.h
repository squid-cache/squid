
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

#ifndef SQUID_CONFIGPARSER_H
#define SQUID_CONFIGPARSER_H

#include "SquidString.h"
#include <queue>
#if HAVE_STRING
#include <string>
#endif

class wordlist;
/**
 * Limit to how long any given config line may be.
 * This affects squid.conf and all included files.
 *
 * Behaviour when setting larger than 2KB is unknown.
 * The config parser read mechanism can cope, but the other systems
 * receiving the data from its buffers on such lines may not.
 */
#define CONFIG_LINE_LIMIT	2048

/**
 * A configuration file Parser. Instances of this class track
 * parsing state and perform tokenisation. Syntax is currently
 * taken care of outside this class.
 *
 * One reason for this class is to allow testing of configuration
 * using modules without linking cache_cf.o in - because that drags
 * in all of squid by reference. Instead the tokeniser only is
 * brought in.
 */
class ConfigParser
{

public:
    void destruct();
    static void ParseUShort(unsigned short *var);
    static void ParseBool(bool *var);
    static void ParseString(char **var);
    static void ParseString(String *var);
    /// Parse an unquoted token (no spaces) or a "quoted string" that
    /// may include spaces. In some contexts, quotes strings may also
    /// include macros. Quoted strings may escape any character with
    /// a backslash (\), which is currently only useful for inner
    /// quotes. TODO: support quoted strings anywhere a token is accepted.
    static void ParseQuotedString(char **var, bool *wasQuoted = NULL);
    static void ParseQuotedString(String *var, bool *wasQuoted = NULL);
    static const char *QuoteString(const String &var);
    static void ParseWordList(wordlist **list);
    static char * strtokFile();
    static void strtokFileUndo();
    static void strtokFilePutBack(const char *);

    /**
      Returns the body of the next element. The element is either a token or
      a quoted string with optional escape sequences and/or macros. The body
      of a quoted string element does not include quotes or escape sequences.
      Future code will want to see Elements and not just their bodies.
    */
    static char *NextToken();

    /// configuration_includes_quoted_values in squid.conf
    static int RecognizeQuotedValues;

protected:
    static char *NextElement(bool *wasQuoted);
    static char *StripComment(char *token);

private:
    static char *lastToken;
    static std::queue<std::string> undo;
};

int parseConfigFile(const char *file_name);

/// Used for temporary hacks to allow old code to handle quoted values
/// without replacing every strtok() call.
extern char *xstrtok(char *str, const char *delimiters);

#endif /* SQUID_CONFIGPARSER_H */
