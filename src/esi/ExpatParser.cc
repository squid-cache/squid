
/*
 * $Id$
 *
 * DEBUG: section 86    ESI processing
 * AUTHOR: Robert Collins
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"

#if USE_SQUID_ESI

#include "esi/ExpatParser.h"

EsiParserDefinition(ESIExpatParser);

ESIExpatParser::ESIExpatParser(ESIParserClient *aClient) : theClient (aClient)
{
    /* TODO: grab the document encoding from the headers */
    p = XML_ParserCreateNS(NULL,'|');
    XML_SetUserData (myParser(), static_cast<void *>(this));
    XML_SetElementHandler(myParser(), Start, End);
    XML_SetDefaultHandler(myParser(), Default);
    XML_SetCommentHandler(myParser(), Comment);
    XML_UseParserAsHandlerArg(myParser());
}

ESIExpatParser::~ESIExpatParser()
{
    XML_ParserFree (myParser());
    p = NULL;
}

void
ESIExpatParser::Start(void *data,const XML_Char *el, const char **attr)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->start (el, attr, XML_GetSpecifiedAttributeCount (parser));
}

void
ESIExpatParser::End(void *data,const XML_Char *el)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->end (el);
}

void
ESIExpatParser::Default(void *data, const XML_Char *s, int len)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->parserDefault (s, len);
}

void
ESIExpatParser::Comment(void *data, const XML_Char *s)
{
    XML_Parser parser = static_cast<XML_Parser>(data);
    ESIExpatParser *me = (ESIExpatParser *)XML_GetUserData(parser);
    me->theClient->parserComment (s);
}

bool
ESIExpatParser::parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream)
{
    return XML_Parse(myParser(), dataToParse, lengthOfData, endOfStream);
}

long int
ESIExpatParser::lineNumber() const
{
    return (long int)XML_GetCurrentLineNumber(myParser());
}

char const *
ESIExpatParser::errorString() const
{
    return XML_ErrorString(XML_GetErrorCode(myParser()));
}

#endif /* USE_SQUID_ESI */
