/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ESICUSTOMPARSER_H
#define SQUID_ESICUSTOMPARSER_H

class Trie;

/* inherits from */
#include "esi/Parser.h"

#include "SBuf.h"
#include "SquidString.h"

/**
 \ingroup ESIAPI
 */
class ESICustomParser : public ESIParser
{

public:
    ESICustomParser(ESIParserClient *);
    ~ESICustomParser();
    /* true on success */
    bool parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream);
    long int lineNumber() const;
    char const * errorString() const;

    EsiParserDeclaration;

private:
    static Trie *SearchTrie;
    static Trie *GetTrie();
    enum ESITAG_t {
        ESITAG=1,
        ESIENDTAG=2,
        ESICOMMENT=3
    };

    char const *findTag(char const *a, size_t b);
    ESIParserClient *theClient;
    String error;
    /* cheap n dirty - buffer it all */
    SBuf content;
    /* TODO: make a class of this type code */
    ESITAG_t lastTag;
};

#endif /* SQUID_ESICUSTOMPARSER_H */

