/*
 * $Id: ESILibxml2Parser.h,v 1.3 2005/07/03 15:25:08 serassio Exp $
 *
 * AUTHOR: Joachim Bauch (mail@joachim-bauch.de)
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

/*
 * The ESI Libxml2 parser is Copyright (c) 2004 by Joachim Bauch
 * http://www.joachim-bauch.de
 * mail@joachim-bauch.de
 */

#ifndef SQUID_ESILIBXML2PARSER_H
#define SQUID_ESILIBXML2PARSER_H

#include "ESIParser.h"
// workaround for definition of "free" that prevents include of
// parser.h from libxml2 without errors
#ifdef free
#define OLD_FREE free
#undef free
#endif
#include <libxml/parser.h>
#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#ifdef OLD_FREE
#define free OLD_FREE
#endif

class ESILibxml2Parser : public ESIParser
{

public:
    ESILibxml2Parser(ESIParserClient *);
    ~ESILibxml2Parser();
    /* true on success */
    bool parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream);
    long int lineNumber() const;
    char const * errorString() const;

    ESIParserClient *getClient() { return theClient; }

private:
    ESI_PARSER_TYPE;
    mutable xmlParserCtxtPtr parser; /* our parser */

    ESIParserClient *theClient;
};

#endif /* SQUID_ESILIBXML2PARSER_H */
