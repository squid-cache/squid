/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * The ESI Libxml2 parser is Copyright (c) 2004 by Joachim Bauch
 * http://www.joachim-bauch.de
 * mail@joachim-bauch.de
 */

#ifndef SQUID_ESILIBXML2PARSER_H
#define SQUID_ESILIBXML2PARSER_H

#if USE_SQUID_ESI && HAVE_LIBXML2

#include "esi/Parser.h"
// workaround for definition of "free" that prevents include of
// parser.h from libxml2 without errors
#ifdef free
#define OLD_FREE free
#undef free
#endif

#if __clang__
// workaround for clang complaining of unknown attributes in libxml2 on fedora22
#ifdef LIBXML_ATTR_ALLOC_SIZE
#undef LIBXML_ATTR_ALLOC_SIZE
#endif
#define LIBXML_ATTR_ALLOC_SIZE(x)
#endif /* __clang__ */

#if HAVE_LIBXML_PARSER_H
#include <libxml/parser.h>
#endif
#if HAVE_LIBXML_HTMLPARSER_H
#include <libxml/HTMLparser.h>
#endif
#if HAVE_LIBXML_HTMLTREE_H
#include <libxml/HTMLtree.h>
#endif

#ifdef OLD_FREE
#define free OLD_FREE
#endif

class ESILibxml2Parser : public ESIParser
{

public:
    ESILibxml2Parser(ESIParserClient *);
    ~ESILibxml2Parser() override;
    /* true on success */
    bool parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream) override;
    long int lineNumber() const override;
    char const * errorString() const override;

    ESIParserClient *getClient() { return theClient; }

    EsiParserDeclaration;

private:
    mutable xmlParserCtxtPtr parser; /* our parser */

    ESIParserClient *theClient;
};

#endif /* USE_SQUID_ESI */

#endif /* SQUID_ESILIBXML2PARSER_H */

