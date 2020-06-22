/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_NOTES_H
#define SQUID_NOTES_H

#include "acl/forward.h"
#include "base/RefCount.h"
#include "format/Format.h"
#include "mem/forward.h"
#include "SquidString.h"

#include <string>
#include <vector>

class HttpRequest;
class HttpReply;
class AccessLogEntry;
class NotePairs;

typedef RefCount<AccessLogEntry> AccessLogEntryPointer;
typedef RefCount<NotePairs> NotePairsPointer;

/**
 * Used to store a note configuration. The notes are custom key:value
 * pairs ICAP request headers or ECAP options used to pass
 * custom transaction-state related meta information to squid
 * internal subsystems or to adaptation services.
 */
class Note: public RefCountable
{
public:
    typedef RefCount<Note> Pointer;

    /// Stores a value for the note.
    class Value: public RefCountable
    {
    public:
        typedef RefCount<Value> Pointer;
        friend class Note;

        enum Method { mhReplace, mhAppend };

        Value(const char *aVal, const bool quoted, const char *descr, const Method method = mhReplace);
        ~Value();
        Value(const Value&) = delete;
        Value &operator=(const Value&) = delete;

        Method method() const { return theMethod; }
        const SBuf &value() const { return theValue; }

        ACLList *aclList; ///< The access list used to determine if this value is valid for a request

    private:
        /// \return the formatted value with expanded logformat %macros (quoted values).
        /// \return the original value (non-quoted values).
        const SBuf &format(const AccessLogEntryPointer &al);

        Format::Format *valueFormat; ///< Compiled annotation value format.
        SBuf theValue; ///< Configured annotation value, possibly with %macros.
        /// The expanded value produced by format(), empty for non-quoted values.
        SBuf theFormattedValue;
        /// Specifies how theValue will be applied to the existing annotation
        /// with the same key: it either replaces the existing value or is appended
        /// to the list of existing values.
        Method theMethod;
    };
    typedef std::vector<Value::Pointer> Values;

    Note(const char *aKey, const size_t keyLen): theKey(aKey, keyLen) {}
    explicit Note(const SBuf aKey): theKey(aKey) {}
    Note(const Note&) = delete;
    Note &operator=(const Note&) = delete;

    /// Adds a value to the note and returns a pointer to the
    /// related Value object.
    Value::Pointer addValue(const char *value, const bool quoted, const char *descr,
                            const Value::Method m = Value::mhAppend);

    /// Walks through the  possible values list of the note, selects
    /// the first value, matching the given HttpRequest and HttpReply
    /// and assigns the given 'matched' to it.
    /// \return true if matched, false otherwise
    bool match(HttpRequest *request, HttpReply *reply, const AccessLogEntryPointer &al, SBuf &matched);
    const SBuf &key() const { return theKey; }
    void updateNotePairs(NotePairsPointer pairs, const CharacterSet *delimiters, const AccessLogEntryPointer &al);
    /// Dump the single Note to the given StoreEntry object.
    void dump(StoreEntry *entry, const char *key);
    /// For the key and all its Values compile a string of
    /// "Key: Value" pairs separated by sep string.
    SBuf toString(const char *sep) const;

private:
    SBuf theKey; ///< The note key
    Values values; ///< The possible values list for the note
};

class ConfigParser;

/**
 * Used to store a notes configuration list.
 */
class Notes : public RefCountable
{
public:
    typedef RefCount<Notes> Pointer;
    typedef std::vector<SBuf> Keys; ///< unordered annotation names
    typedef std::vector<Note::Pointer> NotesList;
    typedef NotesList::iterator iterator; ///< iterates over the notes list
    typedef NotesList::const_iterator const_iterator; ///< iterates over the notes list

    explicit Notes(const char *aDescr, const Keys *extraBlacklist = nullptr, bool allowFormatted = true);
    Notes() = default;
    ~Notes() { notes.clear(); }
    Notes(const Notes&) = delete;
    Notes &operator=(const Notes&) = delete;

    /// Parses a notes line and returns a pointer to the parsed Note object.
    Note::Pointer parse(ConfigParser &parser);

    /// Parses an annotate line with "key=value" or "key+=value" formats.
    void parseKvPair();

    /// Dump the notes list to the given StoreEntry object.
    void dump(StoreEntry *entry, const char *name);
    /// clean the notes list
    void clean() { notes.clear(); }

    /// points to the first argument
    iterator begin() { return notes.begin(); }
    /// points to the end of list
    iterator end() { return notes.end(); }
    /// \returns true if the notes list is empty
    bool empty() const { return notes.empty(); }
    /// Convert Notes list to a string consist of "Key: Value"
    /// entries separated by sep string.
    const char *toString(const char *sep = "\r\n") const;
    void updateNotePairs(NotePairsPointer pairs, const CharacterSet *delimiters,
                         const AccessLogEntryPointer &al);
private:
    /// Makes sure the given key is not on the given list of banned names.
    void banReservedKey(const SBuf &key, const Keys &banned) const;

    /// Verifies that the key is not blacklisted (fatal error) and
    /// does not contain special characters (non-fatal error).
    void validateKey(const SBuf &key) const;

    /// Adds a note to the notes list and returns a pointer to the
    /// related Note object. If the note key already exists in list,
    /// returns a pointer to the existing object.
    /// If keyLen is not provided, the noteKey is assumed null-terminated.
    Note::Pointer add(const SBuf &noteKey);
    Note::Pointer find(const SBuf &noteKey);

    NotesList notes; ///< The Note::Pointer objects array list
    const char *descr = nullptr; ///< identifies note source in error messages

    Keys blacklist; ///< a list of additional prohibited key names
    bool formattedValues = false; ///< whether to expand quoted logformat %codes

    static const Notes::Keys &BlackList(); ///< always prohibited key names
};

/**
 * Used to store list of notes
 */
class NotePairs: public RefCountable
{
public:
    typedef RefCount<NotePairs> Pointer;

    /// Used to store a note key/value pair.
    class Entry : public RefCountable
    {
        MEMPROXY_CLASS(Entry);
    public:
        typedef RefCount<Entry> Pointer;

        Entry(const SBuf &aKey, const SBuf &aValue)
            : theName(aKey), theValue(aValue) {}
        Entry(const char *aKey, const char *aValue)
            : theName(aKey), theValue(aValue) {}
        Entry(const Entry &) = delete;
        Entry &operator=(const Entry &) = delete;

        const SBuf &name() const { return theName; }
        const SBuf &value() const { return theValue; }

    private:
        SBuf theName;
        SBuf theValue;
    };
    typedef std::vector<Entry::Pointer> Entries;      ///< The key/value pair entries
    typedef std::vector<SBuf> Names;

    NotePairs() {}
    NotePairs &operator=(NotePairs const &) = delete;
    NotePairs(NotePairs const &) = delete;

    /// Append the entries of the src NotePairs list to our list.
    void append(const NotePairs *src);

    /// Replace existing list entries with the src NotePairs entries.
    /// Do not replace but append entries named in the appendables
    /// Entries which do not exist in the destination set are added.
    void replaceOrAddOrAppend(const NotePairs *src, const Names &appendables);

    /// Replace existing list entries with the src NotePairs entries.
    /// Entries which do not exist in the destination set are added.
    void replaceOrAdd(const NotePairs *src);

    /// Append any new entries of the src NotePairs list to our list.
    /// Entries which already exist in the destination set are ignored.
    void appendNewOnly(const NotePairs *src);

    /// \param resultNote a comma separated list of notes with key 'noteKey'.
    /// \returns true if there are entries with the given 'noteKey'.
    /// Use findFirst() instead when a unique kv-pair is needed.
    bool find(SBuf &resultNote, const char *noteKey, const char *sep = ",") const;

    /// \returns the first note value for this key or an empty string.
    const char *findFirst(const char *noteKey) const;

    /// Adds a note key and value to the notes list.
    /// If the key name already exists in the list, add the given value to its set
    /// of values.
    void add(const SBuf &key, const SBuf &value);
    void add(const char *key, const char *value);

    /// Remove all notes with a given key. If keyLen is not
    /// provided, the key is assumed null-terminated.
    void remove(const char *key);
    void remove(const SBuf &key);

    /// Adds a note key and values strList to the notes list.
    /// If the key name already exists in the list, add the new values to its set
    /// of values.
    void addStrList(const SBuf &key, const SBuf &values, const CharacterSet &delimiters);

    /// \returns true if the key/value pair is already stored
    bool hasPair(const SBuf &key, const SBuf &value) const;

    /// Convert NotePairs list to a string consist of "Key: Value"
    /// entries separated by sep string.
    const char *toString(const char *sep = "\r\n") const;

    /// \returns true if there are not entries in the list
    bool empty() const {return entries.empty();}

    void clear() { entries.clear(); }

    /// If delimiters are provided, returns another Entries, converting each single multi-token
    /// pair to multiple single-token pairs; returns existing entries otherwise.
    const Entries &expandListEntries(const CharacterSet *delimiters) const;

private:
    Entries entries; ///< The key/value pair entries
};

#endif

