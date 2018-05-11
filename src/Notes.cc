/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/FilledChecklist.h"
#include "acl/Gadgets.h"
#include "client_side.h"
#include "ConfigParser.h"
#include "globals.h"
#include "http/Stream.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StrList.h"

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
Note::match(HttpRequest *request, HttpReply *reply, const AccessLogEntry::Pointer &al)
{

    typedef Values::iterator VLI;
    ACLFilledChecklist ch(NULL, request, NULL);
    ch.al = al;
    ch.reply = reply;
    ch.syncAle(request, nullptr);
    if (reply)
        HTTPMSGLOCK(ch.reply);

    for (VLI i = values.begin(); i != values.end(); ++i ) {
        const auto ret= ch.fastCheck((*i)->aclList);
        debugs(93, 5, HERE << "Check for header name: " << key << ": " << (*i)->value
               <<", HttpRequest: " << request << " HttpReply: " << reply << " matched: " << ret);
        if (ret.allowed()) {
            if (al != NULL && (*i)->valueFormat != NULL) {
                static MemBuf mb;
                mb.reset();
                (*i)->valueFormat->assemble(mb, al, 0);
                return mb.content();
            } else
                return (*i)->value.termedBuf();
        }
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
    String key = ConfigParser::NextToken();
    ConfigParser::EnableMacros();
    String value = ConfigParser::NextQuotedToken();
    ConfigParser::DisableMacros();
    bool valueWasQuoted = ConfigParser::LastTokenWasQuoted();
    Note::Pointer note = add(key);
    Note::Value::Pointer noteValue = note->addValue(value);

    String label(key);
    label.append('=');
    label.append(value);
    aclParseAclList(parser, &noteValue->aclList, label.termedBuf());
    if (formattedValues && valueWasQuoted) {
        noteValue->valueFormat =  new Format::Format(descr ? descr : "Notes");
        noteValue->valueFormat->parse(value.termedBuf());
    }
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
    notes.clear();
}

NotePairs::~NotePairs()
{
    while (!entries.empty()) {
        delete entries.back();
        entries.pop_back();
    }
}

const char *
NotePairs::find(const char *noteKey, const char *sep) const
{
    static String value;
    value.clean();
    for (std::vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(noteKey) == 0) {
            if (value.size())
                value.append(sep);
            value.append((*i)->value);
        }
    }
    return value.size() ? value.termedBuf() : NULL;
}

const char *
NotePairs::toString(const char *sep) const
{
    static String value;
    value.clean();
    for (std::vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        value.append((*i)->name);
        value.append(": ");
        value.append((*i)->value);
        value.append(sep);
    }
    return value.size() ? value.termedBuf() : NULL;
}

const char *
NotePairs::findFirst(const char *noteKey) const
{
    for (std::vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(noteKey) == 0)
            return (*i)->value.termedBuf();
    }
    return NULL;
}

void
NotePairs::add(const char *key, const char *note)
{
    entries.push_back(new NotePairs::Entry(key, note));
}

void
NotePairs::remove(const char *key)
{
    std::vector<NotePairs::Entry *>::iterator i = entries.begin();
    while (i != entries.end()) {
        if ((*i)->name.cmp(key) == 0) {
            delete *i;
            i = entries.erase(i);
        } else {
            ++i;
        }
    }
}

void
NotePairs::addStrList(const char *key, const char *values)
{
    String strValues(values);
    const char *item;
    const char *pos = NULL;
    int ilen = 0;
    while (strListGetItem(&strValues, ',', &item, &ilen, &pos)) {
        String v;
        v.append(item, ilen);
        entries.push_back(new NotePairs::Entry(key, v.termedBuf()));
    }
}

bool
NotePairs::hasPair(const char *key, const char *value) const
{
    for (std::vector<NotePairs::Entry *>::const_iterator  i = entries.begin(); i != entries.end(); ++i) {
        if ((*i)->name.cmp(key) == 0 && (*i)->value.cmp(value) == 0)
            return true;
    }
    return false;
}

void
NotePairs::append(const NotePairs *src)
{
    for (std::vector<NotePairs::Entry *>::const_iterator  i = src->entries.begin(); i != src->entries.end(); ++i) {
        entries.push_back(new NotePairs::Entry((*i)->name.termedBuf(), (*i)->value.termedBuf()));
    }
}

void
NotePairs::appendNewOnly(const NotePairs *src)
{
    for (std::vector<NotePairs::Entry *>::const_iterator  i = src->entries.begin(); i != src->entries.end(); ++i) {
        if (!hasPair((*i)->name.termedBuf(), (*i)->value.termedBuf()))
            entries.push_back(new NotePairs::Entry((*i)->name.termedBuf(), (*i)->value.termedBuf()));
    }
}

void
NotePairs::replaceOrAdd(const NotePairs *src)
{
    for (std::vector<NotePairs::Entry *>::const_iterator  i = src->entries.begin(); i != src->entries.end(); ++i) {
        remove((*i)->name.termedBuf());
    }
    append(src);
}

NotePairs &
SyncNotes(AccessLogEntry &ale, HttpRequest &request)
{
    // XXX: auth code only has access to HttpRequest being authenticated
    // so we must handle the case where HttpRequest is set without ALE being set.

    if (!ale.notes) {
        if (!request.notes)
            request.notes = new NotePairs;
        ale.notes = request.notes;
    } else {
        assert(ale.notes == request.notes);
    }
    return *ale.notes;
}

void
UpdateRequestNotes(ConnStateData *csd, HttpRequest &request, NotePairs const &helperNotes)
{
    // Tag client connection if the helper responded with clt_conn_tag=tag.
    if (const char *connTag = helperNotes.findFirst("clt_conn_tag")) {
        if (csd)
            csd->connectionTag(connTag);
    }
    if (!request.notes)
        request.notes = new NotePairs;
    request.notes->replaceOrAdd(&helperNotes);
}

