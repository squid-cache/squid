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

    /**
     * Returns the first value for this key or an empty string.
     */
    const char *firstValue() const { return (values.size()>0&&values[0]->value.defined()?values[0]->value.termedBuf():""); }

    String key; ///< The note key
    Values values; ///< The possible values list for the note
};

class ConfigParser;
/**
 * Used to store a notes list.
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

    /**
     * Adds a note key and value to the notes list.
     * If the key name already exists in list, add the given value to its set of values.
     */
    void add(const String &noteKey, const String &noteValue);

    /**
     * Adds a set of notes from another notes list to this set.
     * Creating entries for any new keys needed.
     * If the key name already exists in list, add the given value to its set of values.
     *
     * WARNING:
     * The list entries are all of shared Pointer type. Altering the src object(s) after
     * using this function will update both Notes lists. Likewise, altering this
     * destination NotesList will affect any relevant copies of src still in use.
     */
    void add(const Notes &src);

    /**
     * Returns a pointer to an existing Note with given key name or nil.
     */
    Note::Pointer find(const String &noteKey) const;

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

class NotePairs : public HttpHeader
{
public:
    NotePairs() : HttpHeader(hoNote) {}

    /// convert a NotesList into a NotesPairs
    /// appending to any existing entries already present
    void append(const Notes::NotesList &src) {
        for (Notes::NotesList::const_iterator m = src.begin(); m != src.end(); ++m)
            for (Note::Values::iterator v =(*m)->values.begin(); v != (*m)->values.end(); ++v)
                putExt((*m)->key.termedBuf(), (*v)->value.termedBuf());
    }

    void append(const NotePairs *src) {
        HttpHeader::append(dynamic_cast<const HttpHeader*>(src));
    }
};

#endif
