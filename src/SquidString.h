/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 67    String */

#ifndef SQUID_STRING_H
#define SQUID_STRING_H

#include "base/TextException.h"
#include "Debug.h"

#include <ostream>

/* squid string placeholder (for printf) */
#ifndef SQUIDSTRINGPH
#define SQUIDSTRINGPH "%.*s"
#define SQUIDSTRINGPRINT(s) (s).psize(),(s).rawBuf()
#endif /* SQUIDSTRINGPH */

class String
{

public:
    String();
    String(char const *);
    String(String const &);
    String(String && S) : size_(S.size_), len_(S.len_), buf_(S.buf_) {
        S.buf_ = nullptr; // S is about to be destructed
        S.size_ = S.len_ = 0;
    }
    ~String();

    typedef size_t size_type; //storage size intentionally unspecified
    const static size_type npos = static_cast<size_type>(-1);

    String &operator =(char const *);
    String &operator =(String const &);
    String &operator =(String && S) {
        if (this != &S) {
            clean();
            size_ = S.size_;
            len_ = S.len_;
            buf_ = S.buf_;
            S.size_ = 0;
            S.len_ = 0;
            S.buf_ = nullptr; // S is about to be destructed
        }
        return *this;
    }

    bool operator ==(String const &) const;
    bool operator !=(String const &) const;

    /**
     * Retrieve a single character in the string.
     \param aPos Position of character to retrieve.
     */
    char operator [](unsigned int aPos) const {
        assert(aPos < size_);
        return buf_[aPos];
    }

    /// The absolute size limit on data held in a String.
    /// Since Strings can be nil-terminated implicitly it is best to ensure
    /// the useful content length is strictly less than this limit.
    static size_type SizeMaxXXX() { return SizeMax_; }

    size_type size() const { return len_; }

    /// variant of size() suited to be used for printf-alikes.
    /// throws when size() >= INT_MAX
    int psize() const {
        Must(size() < INT_MAX);
        return size();
    }

    /**
     * Returns a raw pointer to the underlying backing store. The caller has been
     * verified not to make any assumptions about null-termination
     */
    char const * rawBuf() const { return buf_; }

    /**
     * Returns a raw pointer to the underlying backing store.
     * The caller requires it to be null-terminated.
     */
    char const * termedBuf() const { return buf_; }

    void assign(const char *str, int len);
    void clean();
    void reset(char const *str);
    void append(char const *buf, int len);
    void append(char const *buf);
    void append(char const);
    void append(String const &);
    void absorb(String &old);
    const char * pos(char const *aString) const;
    const char * pos(char const ch) const;
    ///offset from string start of the first occurrence of ch
    /// returns String::npos if ch is not found
    size_type find(char const ch) const;
    size_type find(char const *aString) const;
    const char * rpos(char const ch) const;
    size_type rfind(char const ch) const;
    int cmp(char const *) const;
    int cmp(char const *, size_type count) const;
    int cmp(String const &) const;
    int caseCmp(char const *) const;
    int caseCmp(char const *, size_type count) const;
    int caseCmp(String const &str) const {
        return caseCmp(str.rawBuf(),str.size());
    }

    /// Whether creating a totalLen-character string is safe (i.e., unlikely to assert).
    /// Optional extras can be used for overflow-safe length addition.
    /// Implementation has to add 1 because many String allocation methods do.
    static bool CanGrowTo(size_type totalLen, const size_type extras = 0) { return SafeAdd(totalLen, extras) && SafeAdd(totalLen, 1); }
    /// whether appending growthLen characters is safe (i.e., unlikely to assert)
    bool canGrowBy(const size_type growthLen) const { return CanGrowTo(size(), growthLen); }

    String substr(size_type from, size_type to) const;

    void cut(size_type newLength);

private:
    void allocAndFill(const char *str, int len);
    void allocBuffer(size_type sz);
    void setBuffer(char *buf, size_type sz);

    bool defined() const {return buf_!=NULL;}
    bool undefined() const {return !defined();}

    /* never reference these directly! */
    size_type size_ = 0; /* buffer size; limited by SizeMax_ */

    size_type len_ = 0;  /* current length  */

    static const size_type SizeMax_ = 65535; ///< 64K limit protects some fixed-size buffers
    /// returns true after increasing the first argument by extra if the sum does not exceed SizeMax_
    static bool SafeAdd(size_type &base, size_type extra) { if (extra <= SizeMax_ && base <= SizeMax_ - extra) { base += extra; return true; } return false; }

    char *buf_ = nullptr;

    void set(char const *loc, char const ch) {
        if (loc < buf_ || loc > (buf_ + size_))
            return;
        buf_[loc-buf_] = ch;
    }

    void cutPointer(char const *loc) {
        if (loc < buf_ || loc > (buf_ + size_))
            return;
        len_ = loc-buf_;
        buf_[len_] = '\0';
    }
};

inline std::ostream & operator<<(std::ostream &os, String const &aString)
{
    os.write(aString.rawBuf(),aString.size());
    return os;
}

inline bool operator<(const String &a, const String &b)
{
    return a.cmp(b) < 0;
}

const char *checkNullString(const char *p);
int stringHasWhitespace(const char *);
int stringHasCntl(const char *);
char *strwordtok(char *buf, char **t);

#endif /* SQUID_STRING_H */

