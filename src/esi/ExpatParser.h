/*
 * $Id$
 *
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

#ifndef SQUID_ESIEXPATPARSER_H
#define SQUID_ESIEXPATPARSER_H

#if USE_SQUID_ESI

#include "esi/Parser.h"
#include <expat.h>

class ESIExpatParser : public ESIParser
{

public:
    ESIExpatParser(ESIParserClient *);
    ~ESIExpatParser();

    /** \retval true	on success */
    bool parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream);

    long int lineNumber() const;
    char const * errorString() const;

    EsiParserDeclaration;

private:
    /** our parser */
    mutable XML_Parser p;
    static void Start(void *data, const XML_Char *el, const char **attr);
    static void End(void *data, const XML_Char *el);
    static void Default (void *data, const XML_Char *s, int len);
    static void Comment (void *data, const XML_Char *s);
    XML_Parser &myParser() const {return p;}

    ESIParserClient *theClient;
};

#endif /* USE_SQUID_ESI */

#endif /* SQUID_ESIEXPATPARSER_H */
