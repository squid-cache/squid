/*
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

#include "squid.h"
#include "globals.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "ConfigParser.h"
#include "HttpRequest.h"
#include "HttpReply.h"
#include "SquidConfig.h"
#include "Store.h"

#include <algorithm>
#include <string>

Note::Value::~Value()
{
    aclDestroyAclList(&aclList);
}

Note::Value::Pointer
Note::addValue(const String &value)
{
    Value::Pointer v = new Value(value);
    values.push_back(v);
    return v;
}

const char *
Note::match(HttpRequest *request, HttpReply *reply)
{

    typedef Values::iterator VLI;
    ACLFilledChecklist ch(NULL, request, NULL);
    if (reply)
        ch.reply = HTTPMSGLOCK(reply);

    for (VLI i = values.begin(); i != values.end(); ++i ) {
        const int ret= ch.fastCheck((*i)->aclList);
        debugs(93, 5, HERE << "Check for header name: " << key << ": " << (*i)->value
               <<", HttpRequest: " << request << " HttpReply: " << reply << " matched: " << ret);
        if (ret == ACCESS_ALLOWED)
            return (*i)->value.termedBuf();
    }
    return NULL;
}

Note::Pointer
Notes::add(const String &noteKey)
{
    typedef Notes::NotesList::iterator AMLI;
    for (AMLI i = notes.begin(); i != notes.end(); ++i) {
        if ((*i)->key == noteKey)
            return (*i);
    }

    Note::Pointer note = new Note(noteKey);
    notes.push_back(note);
    return note;
}

Note::Pointer
Notes::parse(ConfigParser &parser)
{
    String key, value;
    ConfigParser::ParseString(&key);
    ConfigParser::ParseQuotedString(&value);
    Note::Pointer note = add(key);
    Note::Value::Pointer noteValue = note->addValue(value);
    aclParseAclList(parser, &noteValue->aclList);

    if (blacklisted) {
        for (int i = 0; blacklisted[i] != NULL; ++i) {
            if (note->key.caseCmp(blacklisted[i]) == 0) {
                fatalf("%s:%d: meta key \"%s\" is a reserved %s name",
                       cfg_filename, config_lineno, note->key.termedBuf(),
                       descr ? descr : "");
            }
        }
    }

    return note;
}

void
Notes::dump(StoreEntry *entry, const char *key)
{
    typedef Notes::NotesList::iterator AMLI;
    for (AMLI m = notes.begin(); m != notes.end(); ++m) {
        typedef Note::Values::iterator VLI;
        for (VLI v =(*m)->values.begin(); v != (*m)->values.end(); ++v ) {
            storeAppendPrintf(entry, "%s " SQUIDSTRINGPH " %s",
                              key, SQUIDSTRINGPRINT((*m)->key), ConfigParser::QuoteString((*v)->value));
            dump_acl_list(entry, (*v)->aclList);
            storeAppendPrintf(entry, "\n");
        }
    }
}

void
Notes::clean()
{
    notes.clean();
}
