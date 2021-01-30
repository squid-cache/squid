/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 67    String */

#include "squid.h"
#include "base/TextException.h"
#include "mgr/Registration.h"
#include "profiler/Profiler.h"
#include "Store.h"

#include <climits>

int
String::psize() const
{
    Must(size() < INT_MAX);
    return size();
}

// low-level buffer allocation,
// does not free old buffer and does not adjust or look at len_
void
String::allocBuffer(String::size_type sz)
{
    PROF_start(StringInitBuf);
    assert (undefined());
    char *newBuffer = (char*)memAllocString(sz, &sz);
    setBuffer(newBuffer, sz);
    PROF_stop(StringInitBuf);
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

String::String(char const *aString) : size_(0), len_(0), buf_(NULL)
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
String::limitInit(const char *str, int len)
{
    clean(); // TODO: optimize to avoid cleaning the buffer we can use
    allocAndFill(str, len);
}

// Allocates the buffer to fit the supplied string and fills it.
// Does not clean.
void
String::allocAndFill(const char *str, int len)
{
    PROF_start(StringAllocAndFill);
    assert(str);
    allocBuffer(len + 1);
    len_ = len;
    memcpy(buf_, str, len);
    buf_[len] = '\0';
    PROF_stop(StringAllocAndFill);
}

String::String(String const &old) : size_(0), len_(0), buf_(NULL)
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
    PROF_start(StringClean);

    /* TODO if mempools has already closed this will FAIL!! */
    if (defined())
        memFreeString(size_, buf_);

    len_ = 0;

    size_ = 0;

    buf_ = NULL;
    PROF_stop(StringClean);
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
    PROF_start(StringReset);
    clean(); // TODO: optimize to avoid cleaning the buffer if we can reuse it
    if (str)
        allocAndFill(str, strlen(str));
    PROF_stop(StringReset);
}

void
String::append( char const *str, int len)
{
    assert(str && len >= 0);

    PROF_start(StringAppend);
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
    PROF_stop(StringAppend);
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
    old.buf_ = NULL;
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
    rv.limitInit(rawBuf()+from,to-from);
    return rv;
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
    return strpbrk(s, w_space) != NULL;
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
    unsigned char *word = NULL;
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
        return NULL;
    return strstr(termedBuf(), aString);
}

const char *
String::pos(char const ch) const
{
    if (undefined())
        return NULL;
    return strchr(termedBuf(), ch);
}

const char *
String::rpos(char const ch) const
{
    if (undefined())
        return NULL;
    return strrchr(termedBuf(), (ch));
}

String::size_type
String::find(char const ch) const
{
    const char *c;
    c=pos(ch);
    if (c==NULL)
        return npos;
    return c-rawBuf();
}

String::size_type
String::find(char const *aString) const
{
    const char *c;
    c=pos(aString);
    if (c==NULL)
        return npos;
    return c-rawBuf();
}

String::size_type
String::rfind(char const ch) const
{
    const char *c;
    c=rpos(ch);
    if (c==NULL)
        return npos;
    return c-rawBuf();
}

#if !_USE_INLINE_
#include "String.cci"
#endif

