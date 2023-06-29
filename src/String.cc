/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/TextException.h"
#include "mgr/Registration.h"
#include "Store.h"

#include <climits>

// low-level buffer allocation,
// does not free old buffer and does not adjust or look at len_
void
String::allocBuffer(String::size_type sz)
{
    assert (undefined());
    char *newBuffer = (char*)memAllocString(sz, &sz);
    setBuffer(newBuffer, sz);
}

// low-level buffer assignment
// does not free old buffer and does not adjust or look at len_
void
String::setBuffer(char *aBuf, String::size_type aSize)
{
    assert(undefined());
    assert(aSize <= SizeMax_);
    buf_ = aBuf;
    size_ = aSize;
}

String::String()
{
#if DEBUGSTRINGS
    StringRegistry::Instance().add(this);
#endif
}

String::String(char const *aString)
{
    if (aString)
        allocAndFill(aString, strlen(aString));
#if DEBUGSTRINGS
    StringRegistry::Instance().add(this);
#endif
}

String &
String::operator =(char const *aString)
{
    reset(aString);
    return *this;
}

String &
String::operator =(String const &old)
{
    clean(); // TODO: optimize to avoid cleaning the buffer we can use
    if (old.size() > 0)
        allocAndFill(old.rawBuf(), old.size());
    return *this;
}

bool
String::operator ==(String const &that) const
{
    if (0 == this->cmp(that))
        return true;

    return false;
}

bool
String::operator !=(String const &that) const
{
    if (0 == this->cmp(that))
        return false;

    return true;
}

// public interface, makes sure that we clean the old buffer first
void
String::assign(const char *str, int len)
{
    clean(); // TODO: optimize to avoid cleaning the buffer we can use
    allocAndFill(str, len);
}

// Allocates the buffer to fit the supplied string and fills it.
// Does not clean.
void
String::allocAndFill(const char *str, int len)
{
    assert(str);
    allocBuffer(len + 1);
    len_ = len;
    memcpy(buf_, str, len);
    buf_[len] = '\0';
}

String::String(String const &old) : size_(0), len_(0), buf_(nullptr)
{
    if (old.size() > 0)
        allocAndFill(old.rawBuf(), old.size());
#if DEBUGSTRINGS

    StringRegistry::Instance().add(this);
#endif
}

void
String::clean()
{
    /* TODO if mempools has already closed this will FAIL!! */
    if (defined())
        memFreeString(size_, buf_);

    len_ = 0;

    size_ = 0;

    buf_ = nullptr;
}

String::~String()
{
    clean();
#if DEBUGSTRINGS

    StringRegistry::Instance().remove(this);
#endif
}

void
String::reset(char const *str)
{
    clean(); // TODO: optimize to avoid cleaning the buffer if we can reuse it
    if (str)
        allocAndFill(str, strlen(str));
}

void
String::append( char const *str, int len)
{
    assert(str && len >= 0);

    if (len_ + len + 1 /*'\0'*/ < size_) {
        xstrncpy(buf_+len_, str, len+1);
        len_ += len;
    } else {
        // Create a temporary string and absorb it later.
        String snew;
        assert(canGrowBy(len)); // otherwise snew.len_ may overflow below
        snew.len_ = len_ + len;
        snew.allocBuffer(snew.len_ + 1);

        if (len_)
            memcpy(snew.buf_, rawBuf(), len_);

        if (len)
            memcpy(snew.buf_ + len_, str, len);

        snew.buf_[snew.len_] = '\0';

        absorb(snew);
    }
}

void
String::append(char const *str)
{
    assert(str);
    append(str, strlen(str));
}

void
String::append(char const chr)
{
    char myString[2];
    myString[0]=chr;
    myString[1]='\0';
    append(myString, 1);
}

void
String::append(String const &old)
{
    append(old.rawBuf(), old.len_);
}

void
String::absorb(String &old)
{
    clean();
    setBuffer(old.buf_, old.size_);
    len_ = old.len_;
    old.size_ = 0;
    old.buf_ = nullptr;
    old.len_ = 0;
}

String
String::substr(String::size_type from, String::size_type to) const
{
//    Must(from >= 0 && from < size());
    Must(from < size());
    Must(to > 0 && to <= size());
    Must(to > from);

    String rv;
    rv.assign(rawBuf()+from, to-from);
    return rv;
}

void
String::cut(String::size_type newLength)
{
    // size_type is size_t, unsigned. No need to check for newLength <0
    if (newLength > len_) return;

    len_ = newLength;

    // buf_ may be nullptr on zero-length strings.
    if (len_ == 0 && !buf_)
        return;

    buf_[newLength] = '\0';
}

/// compare NULL and empty strings because str*cmp() may fail on NULL strings
/// and because we need to return consistent results for strncmp(count == 0).
static bool
nilCmp(const bool thisIsNilOrEmpty, const bool otherIsNilOrEmpty, int &result)
{
    if (!thisIsNilOrEmpty && !otherIsNilOrEmpty)
        return false; // result does not matter

    if (thisIsNilOrEmpty && otherIsNilOrEmpty)
        result = 0;
    else if (thisIsNilOrEmpty)
        result = -1;
    else // otherIsNilOrEmpty
        result = +1;

    return true;
}

int
String::cmp(char const *aString) const
{
    int result = 0;
    if (nilCmp(!size(), (!aString || !*aString), result))
        return result;

    return strcmp(termedBuf(), aString);
}

int
String::cmp(char const *aString, String::size_type count) const
{
    int result = 0;
    if (nilCmp((!size() || !count), (!aString || !*aString || !count), result))
        return result;

    return strncmp(termedBuf(), aString, count);
}

int
String::cmp(String const &aString) const
{
    int result = 0;
    if (nilCmp(!size(), !aString.size(), result))
        return result;

    return strcmp(termedBuf(), aString.termedBuf());
}

int
String::caseCmp(char const *aString) const
{
    int result = 0;
    if (nilCmp(!size(), (!aString || !*aString), result))
        return result;

    return strcasecmp(termedBuf(), aString);
}

int
String::caseCmp(char const *aString, String::size_type count) const
{
    int result = 0;
    if (nilCmp((!size() || !count), (!aString || !*aString || !count), result))
        return result;

    return strncasecmp(termedBuf(), aString, count);
}

#if DEBUGSTRINGS
void
String::stat(StoreEntry *entry) const
{
    storeAppendPrintf(entry, "%p : %d/%d \"%.*s\"\n",this,len_, size_, size(), rawBuf());
}

StringRegistry &
StringRegistry::Instance()
{
    return Instance_;
}

template <class C>
int
ptrcmp(C const &lhs, C const &rhs)
{
    return lhs - rhs;
}

StringRegistry::StringRegistry()
{
#if DEBUGSTRINGS
    Mgr::RegisterAction("strings",
                        "Strings in use in squid", Stat, 0, 1);
#endif
}

void
StringRegistry::add(String const *entry)
{
    entries.insert(entry, ptrcmp);
}

void
StringRegistry::remove(String const *entry)
{
    entries.remove(entry, ptrcmp);
}

StringRegistry StringRegistry::Instance_;

String::size_type memStringCount();

void
StringRegistry::Stat(StoreEntry *entry)
{
    storeAppendPrintf(entry, "%lu entries, %lu reported from MemPool\n", (unsigned long) Instance().entries.elements, (unsigned long) memStringCount());
    Instance().entries.head->walk(Stater, entry);
}

void
StringRegistry::Stater(String const * const & nodedata, void *state)
{
    StoreEntry *entry = (StoreEntry *) state;
    nodedata->stat(entry);
}

#endif

/* TODO: move onto String */
int
stringHasWhitespace(const char *s)
{
    return strpbrk(s, w_space) != nullptr;
}

/* TODO: move onto String */
int
stringHasCntl(const char *s)
{
    unsigned char c;

    while ((c = (unsigned char) *s++) != '\0') {
        if (c <= 0x1f)
            return 1;

        if (c >= 0x7f && c <= 0x9f)
            return 1;
    }

    return 0;
}

/*
 * Similar to strtok, but has some rudimentary knowledge
 * of quoting
 */
char *
strwordtok(char *buf, char **t)
{
    unsigned char *word = nullptr;
    unsigned char *p = (unsigned char *) buf;
    unsigned char *d;
    unsigned char ch;
    int quoted = 0;

    if (!p)
        p = (unsigned char *) *t;

    if (!p)
        goto error;

    while (*p && xisspace(*p))
        ++p;

    if (!*p)
        goto error;

    word = d = p;

    while ((ch = *p)) {
        switch (ch) {

        case '\\':
            if (quoted)
                ++p;

            switch (*p) {

            case 'n':
                ch = '\n';

                break;

            case 'r':
                ch = '\r';

                break;

            default:
                ch = *p;

                break;

            }

            *d = ch;
            ++d;

            if (ch)
                ++p;

            break;

        case '"':
            quoted = !quoted;

            ++p;

            break;

        default:
            if (!quoted && xisspace(*p)) {
                ++p;
                goto done;
            }

            *d = *p;
            ++d;
            ++p;
            break;
        }
    }

done:
    *d = '\0';

error:
    *t = (char *) p;
    return (char *) word;
}

const char *
checkNullString(const char *p)
{
    return p ? p : "(NULL)";
}

const char *
String::pos(char const *aString) const
{
    if (undefined())
        return nullptr;
    return strstr(termedBuf(), aString);
}

const char *
String::pos(char const ch) const
{
    if (undefined())
        return nullptr;
    return strchr(termedBuf(), ch);
}

const char *
String::rpos(char const ch) const
{
    if (undefined())
        return nullptr;
    return strrchr(termedBuf(), (ch));
}

String::size_type
String::find(char const ch) const
{
    const char *c;
    c=pos(ch);
    if (c==nullptr)
        return npos;
    return c-rawBuf();
}

String::size_type
String::find(char const *aString) const
{
    const char *c;
    c=pos(aString);
    if (c==nullptr)
        return npos;
    return c-rawBuf();
}

String::size_type
String::rfind(char const ch) const
{
    const char *c;
    c=rpos(ch);
    if (c==nullptr)
        return npos;
    return c-rawBuf();
}

