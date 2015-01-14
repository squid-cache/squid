/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"
#include "Debug.h"
#include "esi/CustomParser.h"
#include "fatal.h"
#include "libTrie/Trie.h"
#include "libTrie/TrieCharTransform.h"

#include <vector>

Trie *ESICustomParser::SearchTrie=NULL;

EsiParserDefinition(ESICustomParser);

Trie *
ESICustomParser::GetTrie()
{
    if (SearchTrie)
        return SearchTrie;

    SearchTrie = new Trie(new TrieCaseless);

    static const ESITAG_t ESITAG_value = ESITAG;

    assert (SearchTrie->add
            ("<esi:",5,(void *)&ESITAG_value));

    static const ESITAG_t ESIENDTAG_value = ESIENDTAG;

    assert (SearchTrie->add
            ("</esi:",6,(void *)&ESIENDTAG_value));

    static const ESITAG_t ESICOMMENT_value = ESICOMMENT;

    assert (SearchTrie->add
            ("<!--",4,(void *)&ESICOMMENT_value));

    return SearchTrie;
}

ESICustomParser::ESICustomParser(ESIParserClient *aClient) :
    theClient(aClient),
    lastTag(ESITAG)
{}

ESICustomParser::~ESICustomParser()
{
    theClient = NULL;
}

char const *
ESICustomParser::findTag(char const *buffer, size_t bufferLength)
{
    size_t myOffset (0);
    ESITAG_t *resulttype = NULL;

    while (myOffset < bufferLength &&
            (resulttype = static_cast<ESITAG_t *>(GetTrie()->findPrefix (buffer + myOffset, bufferLength - myOffset)))
            == NULL)
        ++myOffset;

    if (myOffset == bufferLength)
        return NULL;

    debugs(86, 9, "ESICustomParser::findTag: found " << *resulttype);

    lastTag = *resulttype;

    return buffer + myOffset;
}

bool
ESICustomParser::parse(char const *dataToParse, size_t const lengthOfData, bool const endOfStream)
{
    debugs(86, 9, "ESICustomParser::parse: Appending data to internal buffer");
    content.append (dataToParse, lengthOfData);

    if (!endOfStream) {
        return true;
    }

    size_t openESITags (0);
    //erring on the safe side. Probably rawBuf would be ok too
    char const *currentPos = content.termedBuf();
    size_t remainingCount = content.size();
    char const *tag = NULL;

    while ((tag = findTag(currentPos, remainingCount))) {
        if (tag - currentPos)
            theClient->parserDefault (currentPos,tag - currentPos);

        switch (lastTag) {

        case ESITAG: {
            ++openESITags;
            char *tagEnd = strchr(const_cast<char *>(tag), '>');

            if (!tagEnd) {
                error = "Could not find end ('>') of tag";
                return false;
            }

            if (tagEnd - tag > (ssize_t)remainingCount) {
                error = "Tag ends beyond the parse buffer.";
                return false;
            }

            if (*(tagEnd - 1) == '/')
                --openESITags;

            char * endofName = strpbrk(const_cast<char *>(tag), w_space);

            if (endofName > tagEnd)
                endofName = const_cast<char *>(tagEnd);

            *endofName = '\0';

            *tagEnd = '\0';

            std::vector<char *>attributes;

            char *attribute = const_cast<char *>(endofName + 1);

            while (attribute > tag && attribute < tagEnd) {
                /* leading spaces */

                while (attribute < tagEnd && (xisspace(*attribute) || (*attribute == '/')))
                    ++attribute;

                if (! (attribute < tagEnd))
                    break;

                /* attribute name */
                attributes.push_back(attribute);

                char *nextSpace = strpbrk(attribute, w_space);

                char *equals = strchr(attribute, '=');

                if (!equals) {
                    error = "Missing attribute value.";
                    return false;
                }

                if (nextSpace && nextSpace < equals)
                    *nextSpace = '\0';
                else
                    *equals = '\0';

                ++equals;

                while (equals < tagEnd && xisspace(*equals))
                    ++equals;

                char sep = *equals;

                if (sep != '\'' && sep != '"') {
                    error = "Unknown identifier (";
                    error.append (sep);
                    error.append (")");
                    return false;
                }

                char *value = equals + 1;
                char *end = strchr(value, sep);

                if (!end) {
                    error = "Missing attribute ending separator (";
                    error.append(sep);
                    error.append(")");
                    return false;
                }
                attributes.push_back(value);
                *end = '\0';
                attribute = end + 1;
            }

            // TODO: after c++11, replace &attributes.front() with attributes.data()
            theClient->start (tag + 1, const_cast<const char **>(&attributes.front()), attributes.size() >> 1);
            /* TODO: attributes */

            if (*(tagEnd - 1) == '/')
                theClient->end (tag + 1);

            remainingCount -= tagEnd - currentPos + 1;

            currentPos = tagEnd + 1;
        }

        break;

        case ESIENDTAG: {
            if (!openESITags)
                return false;

            char const *tagEnd = strchr(tag, '>');

            if (!tagEnd)
                return false;

            if (tagEnd - tag > (ssize_t)remainingCount)
                return false;

            char * endofName = strpbrk(const_cast<char *>(tag), w_space);

            if (endofName > tagEnd)
                endofName = const_cast<char *>(tagEnd);

            *endofName = '\0';

            theClient->end (tag + 2);

            --openESITags;

            remainingCount -= tagEnd - currentPos + 1;

            currentPos = tagEnd + 1;
        }

        break;

        case ESICOMMENT: {
            /* Further optimisation potential:
             * 1) recognize end comments for esi and don't callback on
             * comments.
             * 2) provide the comment length to the caller.
             */
            /* Comments must not be nested, without CDATA
             * and we don't support CDATA
             */
            char *commentEnd = strstr (const_cast<char *>(tag), "-->");

            if (!commentEnd) {
                error = "missing end of comment";
                return false;
            }

            if (commentEnd - tag > (ssize_t)remainingCount) {
                error = "comment ends beyond parse buffer";
                return false;
            }

            *commentEnd = '\0';
            theClient->parserComment (tag + 4);
            remainingCount -= commentEnd - currentPos + 3;
            currentPos = commentEnd + 3;
        }

        break;
        break;

        default:
            fatal ("unknown ESI tag type found");
        };

        /*
         * Find next esi tag (open or closing) or comment
         * send tag, or full comment text
         * rinse
         */
    }

    if (remainingCount)
        theClient->parserDefault (currentPos,remainingCount);

    debugs(86, 5, "ESICustomParser::parse: Finished parsing, will return " << !openESITags);

    if (openESITags)
        error = "ESI Tags still open";

    return !openESITags;
}

long int
ESICustomParser::lineNumber() const
{
    /* We don't track lines in the body */
    return 0;
}

char const *
ESICustomParser::errorString() const
{
    if (error.size())
        return error.termedBuf();
    else
        return "Parsing error strings not implemented";
}

