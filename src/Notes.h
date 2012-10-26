#ifndef SQUID_NOTES_H
#define SQUID_NOTES_H

#include "HttpHeader.h"
#include "HttpHeaderTools.h"
#include "typedefs.h"

#if HAVE_STRING
#include <string>
#endif


class HttpRequest;
class HttpReply;

/**
 * Used to store notes. The notes are custom key:value pairs
 * ICAP request headers or ECAP options used to pass
 * custom transaction-state related meta information to squid
 * internal subsystems or to addaptation services.
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
 * Used to store a notes list.
 */
class Notes {
public:
    typedef Vector<Note::Pointer> NotesList;
    typedef NotesList::iterator iterator; ///< iterates over the notes list

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

class NotePairs : public HttpHeader {
public:
    NotePairs() : HttpHeader(hoNote) {}
};

#endif
