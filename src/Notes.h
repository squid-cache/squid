#ifndef SQUID_NOTES_H
#define SQUID_NOTES_H

#include "acl/forward.h"
#include "base/Vector.h"
#include "base/RefCount.h"
#include "CbDataList.h"
#include "MemPool.h"
#include "SquidString.h"
#include "typedefs.h"

#if HAVE_STRING
#include <string>
#endif

class HttpRequest;
class HttpReply;

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
        String value; ///< a note value
        ACLList *aclList; ///< The access list used to determine if this value is valid for a request
        explicit Value(const String &aVal) : value(aVal), aclList(NULL) {}
        ~Value();
    };
    typedef Vector<Value::Pointer> Values;

    explicit Note(const String &aKey): key(aKey) {}

    /**
     * Adds a value to the note and returns a  pointer to the
     * related Value object.
     */
    Value::Pointer addValue(const String &value);

    /**
     * Walks through the  possible values list of the note and selects
     * the first value which matches the given HttpRequest and HttpReply
     * or NULL if none matches.
     */
    const char *match(HttpRequest *request, HttpReply *reply);

    String key; ///< The note key
    Values values; ///< The possible values list for the note
};

class ConfigParser;
/**
 * Used to store a notes configuration list.
 */
class Notes
{
public:
    typedef Vector<Note::Pointer> NotesList;
    typedef NotesList::iterator iterator; ///< iterates over the notes list
    typedef NotesList::const_iterator const_iterator; ///< iterates over the notes list

    Notes(const char *aDescr, const char **metasBlacklist): descr(aDescr), blacklisted(metasBlacklist) {}
    Notes(): descr(NULL), blacklisted(NULL) {}
    ~Notes() { notes.clean(); }
    /**
     * Parse a notes line and returns a pointer to the
     * parsed Note object.
     */
    Note::Pointer parse(ConfigParser &parser);
    /**
     * Dump the notes list to the given StoreEntry object.
     */
    void dump(StoreEntry *entry, const char *name);
    void clean(); /// clean the notes list

    /// points to the first argument
    iterator begin() { return notes.begin(); }
    /// points to the end of list
    iterator end() { return notes.end(); }
    /// return true if the notes list is empty
    bool empty() { return notes.empty(); }

    NotesList notes; ///< The Note::Pointer objects array list
    const char *descr; ///< A short description for notes list
    const char **blacklisted; ///< Null terminated list of blacklisted note keys

private:
    /**
     * Adds a note to the notes list and returns a pointer to the
     * related Note object. If the note key already exists in list,
     * returns a pointer to the existing object.
     */
    Note::Pointer add(const String &noteKey);
};

/**
 * Used to store list of notes
 */
class NotePairs: public RefCountable
{
public:
    typedef RefCount<NotePairs> Pointer;

    /**
     * Used to store a note key/value pair.
     */
    class Entry
    {
    public:
        Entry(const char *aKey, const char *aValue): name(aKey), value(aValue) {}
        String name;
        String value;
        MEMPROXY_CLASS(Entry);
    };

    NotePairs() {}
    ~NotePairs();

    /**
     * Append the entries of the src NotePairs list to our list.
     */
    void append(const NotePairs *src);

    /**
     * Append any new entries of the src NotePairs list to our list.
     * Entries which already exist in the destination set are ignored.
     */
    void appendNewOnly(const NotePairs *src);

    /**
     * Returns a comma separated list of notes with key 'noteKey'.
     * Use findFirst instead when a unique kv-pair is needed.
     */
    const char *find(const char *noteKey, const char *sep = ",") const;

    /**
     * Returns the first note value for this key or an empty string.
     */
    const char *findFirst(const char *noteKey) const;

    /**
     * Adds a note key and value to the notes list.
     * If the key name already exists in list, add the given value to its set
     * of values.
     */
    void add(const char *key, const char *value);

    /**
     * Remove all notes with a given key.
     */
    void remove(const char *key);

    /**
     * Adds a note key and values strList to the notes list.
     * If the key name already exists in list, add the new values to its set
     * of values.
     */
    void addStrList(const char *key, const char *values);

    /**
     * Return true if the key/value pair is already stored
     */
    bool hasPair(const char *key, const char *value) const;

    /**
     * Convert NotePairs list to a string consist of "Key: Value"
     * entries separated by sep string.
     */
    const char *toString(const char *sep = "\r\n") const;

    /**
     * True if there are not entries in the list
     */
    bool empty() const {return entries.empty();}

    Vector<NotePairs::Entry *> entries;	  ///< The key/value pair entries

private:
    NotePairs &operator = (NotePairs const &); // Not implemented
    NotePairs(NotePairs const &); // Not implemented
};

MEMPROXY_CLASS_INLINE(NotePairs::Entry);

class AccessLogEntry;
/**
 * Keep in sync HttpRequest and the corresponding AccessLogEntry objects
 */
NotePairs &SyncNotes(AccessLogEntry &ale, HttpRequest &request);

#endif
