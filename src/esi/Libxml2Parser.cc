/*
 * $Id$
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
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

#include "squid.h"

#if USE_SQUID_ESI

#include "esi/Libxml2Parser.h"

// the global document that will store the resolved entity
// definitions
static htmlDocPtr entity_doc = NULL;

EsiParserDefinition(ESILibxml2Parser);

// the SAX callback functions
void esi_startElementSAXFunc(void * ctx, const xmlChar * name, const xmlChar ** atts)
{
    int count=0;
    xmlChar **tmp = (xmlChar **)atts;

    while (tmp && *tmp != NULL) {
        count++;
        tmp++;
    }

    // we increased on every key and value
    count /= 2;

    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;

    p->getClient()->start((const char *)name, (const char **)atts, count);
}

void esi_endElementSAXFunc(void * ctx, const xmlChar * name)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->end((const char *)name);
}

void esi_commentSAXFunc(void * ctx, const xmlChar * value)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserComment((const char *)value);
}

void esi_charactersSAXFunc(void *ctx, const xmlChar *ch, int len)
{
    ESILibxml2Parser *p = (ESILibxml2Parser *)ctx;
    p->getClient()->parserDefault((const char *)ch, len);
}

xmlEntityPtr esi_getEntitySAXFunc(void * ctx,  const xmlChar * name)
{
    xmlEntityPtr res = xmlGetDocEntity(entity_doc, name);

    if (res == NULL) {
        const htmlEntityDesc *ent = htmlEntityLookup(name);

        if (ent != NULL) {
            char tmp[32];
            snprintf(tmp, 32, "&#%d;", ent->value);
            res = xmlAddDocEntity(entity_doc, (const xmlChar *)name, XML_INTERNAL_GENERAL_ENTITY, NULL, NULL, (const xmlChar *)tmp);
        }
    }

    return res;
}

ESILibxml2Parser::ESILibxml2Parser(ESIParserClient *aClient) : theClient (aClient)
{
    xmlSAXHandler sax;
    htmlDefaultSAXHandlerInit();
    memset(&sax, 0, sizeof(sax));
    sax.startElement = esi_startElementSAXFunc;
    sax.endElement = esi_endElementSAXFunc;
    sax.comment = esi_commentSAXFunc;
    sax.characters = esi_charactersSAXFunc;
    sax.getEntity = esi_getEntitySAXFunc;

    /* TODO: grab the document encoding from the headers */
    parser = xmlCreatePushParserCtxt(&sax, static_cast<void *>(this), NULL, 0, NULL);
    xmlSetFeature(parser, "substitute entities", 0);

    if (entity_doc == NULL)
        entity_doc = htmlNewDoc(NULL, NULL);
}

ESILibxml2Parser::~ESILibxml2Parser()
{
    xmlFreeParserCtxt(parser);
    parser = NULL;
}

bool
ESILibxml2Parser::parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream)
{
    return (xmlParseChunk(parser, dataToParse, lengthOfData, endOfStream) == 0);
}

long int
ESILibxml2Parser::lineNumber() const
{
    return (long int)xmlSAX2GetLineNumber(parser);
}

char const *
ESILibxml2Parser::errorString() const
{
    xmlErrorPtr error = xmlGetLastError();

    if (error == NULL)
        return NULL;

    return error->message;
}

#endif /* USE_SQUID_ESI */
