/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
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
#include "parser/Tokenizer.h"
#include "sbuf/Stream.h"
#include "sbuf/StringConvert.h"
#include "SquidConfig.h"
#include "Store.h"
#include "StrList.h"

#include <algorithm>
#include <string>

Note::Value::~Value()
{
    aclDestroyAclList(&aclList);
    delete valueFormat;
}

Note::Value::Value(const char *aVal, const bool quoted, const char *descr, const Method m)
    : aclList(nullptr), valueFormat(nullptr), theValue(aVal), theMethod(m)
{
    if (quoted) {
        valueFormat = new Format::Format(descr ? descr : "Notes");
        if (!valueFormat->parse(theValue.c_str())) {
            delete valueFormat;
            SBuf exceptionMsg;
            exceptionMsg.Printf("failed to parse annotation value %s", theValue.c_str());
            throw TexcHere(exceptionMsg.c_str());
        }
    }
}

const SBuf &
Note::Value::format(const AccessLogEntryPointer &al)
{
    if (al && valueFormat) {
        static MemBuf mb;
        mb.reset();
        valueFormat->assemble(mb, al, 0);
        theFormattedValue.assign(mb.content());
        return theFormattedValue;
    }
    return theValue;
}

Note::Value::Pointer
Note::addValue(const char *value, const bool quoted, const char *descr, const Value::Method m)
{
    values.push_back(new Value(value, quoted, descr, m));
    return values.back();
}

bool
Note::match(HttpRequest *request, HttpReply *reply, const AccessLogEntry::Pointer &al, SBuf &matched)
{
    ACLFilledChecklist ch(nullptr, request, nullptr);
    ch.al = al;
    ch.reply = reply;
    ch.syncAle(request, nullptr);
    if (reply)
        HTTPMSGLOCK(ch.reply);

    for (const auto &v: values) {
        assert(v->aclList);
        const auto ret = ch.fastCheck(v->aclList);
        debugs(93, 5, "Check for header name: " << theKey << ": " << v->value() <<
               ", HttpRequest: " << request << " HttpReply: " << reply << " matched: " << ret);
        if (ret.allowed()) {
            matched = v->format(al);
            return true;
        }
    }
    matched.clear();
    return false;
}

void
Note::updateNotePairs(NotePairs::Pointer pairs, const CharacterSet *delimiters, const AccessLogEntryPointer &al)
{
    for (const auto &v: values) {
        const SBuf &formatted = v->format(al);
        if (!pairs->empty() && v->method() == Value::mhReplace)
            pairs->remove(theKey);
        if (delimiters)
            pairs->addStrList(key(), formatted, *delimiters);
        else
            pairs->add(key(), formatted);
    }
}

void
Note::dump(StoreEntry *entry, const char *k)
{
    for (const auto &v: values) {
        storeAppendPrintf(entry, "%s %.*s %s",
                          k, key().length(), key().rawContent(), ConfigParser::QuoteString(SBufToString(v->value())));
        dump_acl_list(entry, v->aclList);
        storeAppendPrintf(entry, "\n");
    }
}

SBuf
Note::toString(const char *sep) const
{
    SBuf result;
    for (const auto &val: values)
        result.appendf("%.*s: %.*s%s", key().length(), key().rawContent(),
                       val->value().length(), val->value().rawContent(), sep);
    return result;
}

const Notes::Keys &
Notes::ReservedKeys()
{
    // these keys are used for internal Squid-helper communication
    static const char *names[] = {
        "group",
        "ha1",
        "log",
        "message",
        "password",
        "rewrite-url",
        "status",
        "tag",
        "ttl",
        "url",
        "user"
    };

    static Keys keys(std::begin(names), std::end(names));
    return keys;
}

Notes::Notes(const char *aDescr, const Keys *extraReservedKeys, bool allowFormatted):
    descr(aDescr),
    formattedValues(allowFormatted)
{
    if (extraReservedKeys)
        reservedKeys = *extraReservedKeys;
}

Note::Pointer
Notes::add(const SBuf &noteKey)
{
    if (Note::Pointer p = find(noteKey))
        return p;
    notes.push_back(new Note(noteKey));
    return notes.back();
}

Note::Pointer
Notes::find(const SBuf &noteKey)
{
    for (const auto &n: notes)
        if (n->key() == noteKey)
            return n;
    return nullptr;
}

void
Notes::banReservedKey(const SBuf &key, const Keys &banned) const
{
    if (std::find(banned.begin(), banned.end(), key) != banned.end())
        throw TextException(ToSBuf("cannot use a reserved ", descr, " name: ", key), Here());
}

void
Notes::validateKey(const SBuf &key) const
{
    banReservedKey(key, ReservedKeys());
    banReservedKey(key, reservedKeys);

    // TODO: fix code duplication: the same set of specials is produced
    // by isKeyNameChar().
    static const CharacterSet allowedSpecials = CharacterSet::ALPHA +
            CharacterSet::DIGIT + CharacterSet("specials", "-_");
    const auto specialIndex = key.findFirstNotOf(allowedSpecials);
    if (specialIndex != SBuf::npos) {
        debugs(28, DBG_CRITICAL, "Warning: used special character '" <<
               key[specialIndex] << "' within annotation name. " <<
               "Future Squid versions will not support this.");
    }
}

Note::Pointer
Notes::parse(ConfigParser &parser)
{
    const char *tok = ConfigParser::NextToken();
    if (!tok)
        fatalf("FATAL: Missing note key");
    SBuf key(tok);
    validateKey(key);
    ConfigParser::EnableMacros();
    const char *val = ConfigParser::NextQuotedToken();
    if (!val)
        fatalf("FATAL: Missing note value");
    ConfigParser::DisableMacros();
    Note::Pointer note = add(key);
    Note::Value::Pointer noteValue = note->addValue(val, formattedValues && ConfigParser::LastTokenWasQuoted(), descr);
    key.append('=');
    key.append(val);
    aclParseAclList(parser, &noteValue->aclList, key.c_str());
    return note;
}

void
Notes::parseKvPair() {
    char *k, *v;
    int parsedPairs = 0;
    while (ConfigParser::NextKvPair(k, v)) {
        int keyLen = strlen(k);
        const Note::Value::Method method = (k[keyLen - 1] == '+') ? Note::Value::mhAppend : Note::Value::mhReplace;
        if (method == Note::Value::mhAppend)
            keyLen--;
        else {
            assert(method == Note::Value::mhReplace);
            if (Note::Pointer oldNote = find(SBuf(k, keyLen)))
                debugs(28, DBG_CRITICAL, "Warning: annotation configuration with key " << k <<
                       " already exists and will be overwritten");
        }
        SBuf key(k, keyLen);
        validateKey(key);
        Note::Pointer note = add(key);
        (void)note->addValue(v, formattedValues && ConfigParser::LastTokenWasQuoted(), descr, method);
        parsedPairs++;
    }
    if (!parsedPairs)
        fatalf("FATAL: Missing annotation kv pair");
}

void
Notes::updateNotePairs(NotePairs::Pointer pairs, const CharacterSet *delimiters, const AccessLogEntry::Pointer &al)
{
    for (const auto &n: notes)
        n->updateNotePairs(pairs, delimiters, al);
}

void
Notes::dump(StoreEntry *entry, const char *key)
{
    for (const auto &n: notes)
        n->dump(entry, key);
}

const char *
Notes::toString(const char *sep) const
{
    static SBuf result;
    result.clear();
    for (const auto &note: notes)
        result.append(note->toString(sep));
    return result.isEmpty() ? nullptr : result.c_str();
}

bool
NotePairs::find(SBuf &resultNote, const char *noteKey, const char *sep) const
{
    resultNote.clear();
    for (const auto &e: entries) {
        if (!e->name().cmp(noteKey)) {
            if (!resultNote.isEmpty())
                resultNote.append(sep);
            resultNote.append(e->value());
        }
    }
    return resultNote.length();
}

const char *
NotePairs::toString(const char *sep) const
{
    static SBuf result;
    result.clear();
    for (const auto &e: entries)
        result.appendf("%.*s: %.*s%s", e->name().length(), e->name().rawContent(),
                       e->value().length(), e->value().rawContent(), sep);
    return result.isEmpty() ? nullptr : result.c_str();
}

const char *
NotePairs::findFirst(const char *noteKey) const
{
    for (const auto &e: entries)
        if (!e->name().cmp(noteKey))
            return const_cast<SBuf &>(e->value()).c_str();
    return nullptr;
}

void
NotePairs::add(const char *key, const char *note)
{
    entries.push_back(new NotePairs::Entry(key, note));
}

void
NotePairs::add(const SBuf &key, const SBuf &note)
{
    entries.push_back(new NotePairs::Entry(key, note));
}

void
NotePairs::remove(const char *key)
{
    Entries::iterator i = entries.begin();
    while (i != entries.end())
        i = (*i)->name().cmp(key) ? i+1 : entries.erase(i);
}

void
NotePairs::remove(const SBuf &key)
{
    Entries::iterator i = entries.begin();
    while (i != entries.end())
        i = (*i)->name() == key ? entries.erase(i) : i+1;
}

static void
AppendTokens(NotePairs::Entries &entries, const SBuf &key, const SBuf &val, const CharacterSet &delimiters)
{
    Parser::Tokenizer tok(val);
    SBuf v;
    while (tok.token(v, delimiters))
        entries.push_back(new NotePairs::Entry(key, v));
    v = tok.remaining();
    if (!v.isEmpty())
        entries.push_back(new NotePairs::Entry(key, v));
}

const NotePairs::Entries &
NotePairs::expandListEntries(const CharacterSet *delimiters) const
{
    if (delimiters) {
        static NotePairs::Entries expandedEntries;
        expandedEntries.clear();
        for (const auto &entry: entries)
            AppendTokens(expandedEntries, entry->name(), entry->value(), *delimiters);
        return expandedEntries;
    }
    return entries;
}

void
NotePairs::addStrList(const SBuf &key, const SBuf &values, const CharacterSet &delimiters)
{
    AppendTokens(entries, key, values, delimiters);
}

bool
NotePairs::hasPair(const SBuf &key, const SBuf &value) const
{
    for (const auto &e: entries)
        if (e->name() == key && e->value() == value)
            return true;
    return false;
}

void
NotePairs::append(const NotePairs *src)
{
    for (const auto &e: src->entries)
        entries.push_back(new NotePairs::Entry(e->name(), e->value()));
}

void
NotePairs::appendNewOnly(const NotePairs *src)
{
    for (const auto &e: src->entries) {
        if (!hasPair(e->name(), e->value()))
            entries.push_back(new NotePairs::Entry(e->name(), e->value()));
    }
}

void
NotePairs::replaceOrAddOrAppend(const NotePairs *src, const NotePairs::Names &appendables)
{
    for (const auto &e: src->entries) {
        if (std::find(appendables.begin(), appendables.end(), e->name()) == appendables.end())
            remove(e->name());
    }
    append(src);
}

void
NotePairs::replaceOrAdd(const NotePairs *src)
{
    for (const auto &e: src->entries)
        remove(e->name());
    append(src);
}

