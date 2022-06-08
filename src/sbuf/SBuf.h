/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 24    SBuf */

#ifndef SQUID_SBUF_H
#define SQUID_SBUF_H

#include "base/InstanceId.h"
#include "base/TextException.h"
#include "Debug.h"
#include "globals.h"
#include "sbuf/forward.h"
#include "sbuf/MemBlob.h"
#include "sbuf/Stats.h"

#include <climits>
#include <iosfwd>
#include <iterator>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

/* SBuf placeholder for printf */
#ifndef SQUIDSBUFPH
#define SQUIDSBUFPH "%.*s"
#define SQUIDSBUFPRINT(s) (s).plength(),(s).rawContent()
#endif /* SQUIDSBUFPH */

// TODO: move within SBuf and rename
typedef enum {
    caseSensitive,
    caseInsensitive
} SBufCaseSensitive;

class CharacterSet;

/** Forward input const_iterator for SBufs
 *
 * Please note that any operation on the underlying SBuf may invalidate
 * all iterators over it, resulting in undefined behavior by them.
 */
class SBufIterator
{
public:
    // iterator traits
    using iterator_category = std::input_iterator_tag;
    using value_type = char;
    using difference_type = std::ptrdiff_t;
    using pointer = char*;
    using reference = char&;

    friend class SBuf;
    typedef MemBlob::size_type size_type;
    bool operator==(const SBufIterator &s) const;
    bool operator!=(const SBufIterator &s) const;

    const char &operator*() const { return *iter; }
    SBufIterator& operator++() { ++iter; return *this; }

protected:
    SBufIterator(const SBuf &, size_type);

    const char *iter = nullptr;
};

/** Reverse input const_iterator for SBufs
 *
 * Please note that any operation on the underlying SBuf may invalidate
 * all iterators over it, resulting in undefined behavior by them.
 */
class SBufReverseIterator : public SBufIterator
{
    friend class SBuf;
public:
    SBufReverseIterator& operator++() { --iter; return *this;}
    const char &operator*() const { return *(iter-1); }
protected:
    SBufReverseIterator(const SBuf &s, size_type sz) : SBufIterator(s,sz) {}
};

/**
 * A String or Buffer.
 * Features: refcounted backing store, cheap copy and sub-stringing
 * operations, copy-on-write to isolate change operations to each instance.
 * Where possible, we're trying to mimic std::string's interface.
 */
class SBuf
{
public:
    typedef MemBlob::size_type size_type;
    typedef SBufIterator const_iterator;
    typedef SBufReverseIterator const_reverse_iterator;
    static const size_type npos = 0xffffffff; // max(uint32_t)

    /// Maximum size of a SBuf. By design it MUST be < MAX(size_type)/2. Currently 256Mb.
    static const size_type maxSize = 0xfffffff;

    /// create an empty (zero-size) SBuf
    SBuf();
    SBuf(const SBuf &S);
    SBuf(SBuf&& S) : store_(std::move(S.store_)), off_(S.off_), len_(S.len_) {
        ++stats.moves;
        S.store_ = nullptr; //RefCount supports nullptr, and S is about to be destructed
        S.off_ = S.len_ = 0;
    }

    /** Constructor: import c-style string
     *
     * Create a new SBuf containing a COPY of the contents of the
     * c-string
     * \param S the c string to be copied
     * \param n how many bytes to import into the SBuf. If it is npos
     *              or unspecified, imports to end-of-cstring
     * \note it is the caller's responsibility not to go out of bounds
     * \note bounds is 0 <= pos < length(); caller must pay attention to signedness
     */
    explicit SBuf(const char *S, size_type n);
    explicit SBuf(const char *S);

    /// Constructor: import std::string. Contents are copied.
    explicit SBuf(const std::string &s);

    ~SBuf();

    /** Explicit assignment.
     *
     * Current SBuf will share backing store with the assigned one.
     */
    SBuf& assign(const SBuf &S);

    /** Assignment operator.
     *
     * Current SBuf will share backing store with the assigned one.
     */
    SBuf& operator =(const SBuf & S) {return assign(S);}
    SBuf& operator =(SBuf &&S) {
        ++stats.moves;
        if (this != &S) {
            store_ = std::move(S.store_);
            off_ = S.off_;
            len_ = S.len_;
            S.store_ = NULL; //RefCount supports NULL, and S is about to be destructed
            S.off_ = 0;
            S.len_ = 0;
        }
        return *this;
    }

    /** Import a c-string into a SBuf, copying the data.
     *
     * It is the caller's duty to free the imported string, if needed.
     * \param S the c string to be copied
     * \param n how many bytes to import into the SBuf. If it is npos
     *              or unspecified, imports to end-of-cstring
     * \note it is the caller's responsibility not to go out of bounds
     * \note to assign a std::string use the pattern:
     *    assign(stdstr.data(), stdstd.length())
     */
    SBuf& assign(const char *S, size_type n);
    SBuf& assign(const char *S) {return assign(S,npos);}

    /** Assignment operator. Copy a NULL-terminated c-style string into a SBuf.
     *
     * Copy a c-style string into a SBuf. Shortcut for SBuf.assign(S)
     * It is the caller's duty to free the imported string, if needed.
     * \note not \0-clean
     */
    SBuf& operator =(const char *S) {return assign(S);}

    /** reset the SBuf as if it was just created.
     *
     * Resets the SBuf to empty, memory is freed lazily.
     */
    void clear();

    /** Append operation
     *
     * Append the supplied SBuf to the current one; extend storage as needed.
     */
    SBuf& append(const SBuf & S);

    /// Append a single character. The character may be NUL (\0).
    SBuf& append(const char c);

    /** Append operation for C-style strings.
     *
     * Append the supplied c-string to the SBuf; extend storage
     * as needed.
     *
     * \param S the c string to be copied. Can be NULL.
     * \param Ssize how many bytes to import into the SBuf. If it is npos
     *              or unspecified, imports to end-of-cstring. If S is NULL,
     *              Ssize is ignored.
     * \note to append a std::string use the pattern
     *     cstr_append(stdstr.data(), stdstd.length())
     */
    SBuf& append(const char * S, size_type Ssize);
    SBuf& append(const char * S) { return append(S,npos); }

    /** Assignment operation with printf(3)-style definition
     * \note arguments may be evaluated more than once, be careful
     *       of side-effects
     */
    SBuf& Printf(const char *fmt, ...);

    /** Append operation with printf-style arguments
     * \note arguments may be evaluated more than once, be careful
     *       of side-effects
     */
    SBuf& appendf(const char *fmt, ...);

    /** Append operation, with vsprintf(3)-style arguments.
     * \note arguments may be evaluated more than once, be careful
     *       of side-effects
     */
    SBuf& vappendf(const char *fmt, va_list vargs);

    /// print the SBuf contents to the supplied ostream
    std::ostream& print(std::ostream &os) const;

    /** print SBuf contents and debug information about the SBuf to an ostream
     *
     * Debug function, dumps to a stream informations on the current SBuf,
     * including low-level details and statistics.
     */
    std::ostream& dump(std::ostream &os) const;

    /** random-access read to any char within the SBuf
     *
     * does not check access bounds. If you need that, use at()
     */
    char operator [](size_type pos) const {++stats.getChar; return store_->mem[off_+pos];}

    /** random-access read to any char within the SBuf.
     *
     * \throw std::exception when access is out of bounds
     * \note bounds is 0 <= pos < length(); caller must pay attention to signedness
     */
    char at(size_type pos) const {checkAccessBounds(pos); return operator[](pos);}

    /** direct-access set a byte at a specified operation.
     *
     * \param pos the position to be overwritten
     * \param toset the value to be written
     * \throw std::exception when pos is of bounds
     * \note bounds is 0 <= pos < length(); caller must pay attention to signedness
     * \note performs a copy-on-write if needed.
     */
    void setAt(size_type pos, char toset);

    /** compare to other SBuf, str(case)cmp-style
     *
     * \param isCaseSensitive one of caseSensitive or caseInsensitive
     * \param n compare up to this many bytes. if npos (default), compare whole SBufs
     * \retval >0 argument of the call is greater than called SBuf
     * \retval <0 argument of the call is smaller than called SBuf
     * \retval 0  argument of the call has the same contents of called SBuf
     */
    int compare(const SBuf &S, const SBufCaseSensitive isCaseSensitive, const size_type n) const;
    int compare(const SBuf &S, const SBufCaseSensitive isCaseSensitive) const {
        return compare(S, isCaseSensitive, npos);
    }

    /// shorthand version for compare()
    inline int cmp(const SBuf &S, const size_type n) const {
        return compare(S,caseSensitive,n);
    }
    inline int cmp(const SBuf &S) const {
        return compare(S,caseSensitive,npos);
    }

    /// shorthand version for case-insensitive compare()
    inline int caseCmp(const SBuf &S, const size_type n) const {
        return compare(S,caseInsensitive,n);
    }
    inline int caseCmp(const SBuf &S) const {
        return compare(S,caseInsensitive,npos);
    }

    /// Comparison with a C-string.
    int compare(const char *s, const SBufCaseSensitive isCaseSensitive, const size_type n) const;
    int compare(const char *s, const SBufCaseSensitive isCaseSensitive) const {
        return compare(s,isCaseSensitive,npos);
    }

    /// Shorthand version for C-string compare().
    inline int cmp(const char *S, const size_type n) const {
        return compare(S,caseSensitive,n);
    }
    inline int cmp(const char *S) const {
        return compare(S,caseSensitive,npos);
    }

    /// Shorthand version for case-insensitive C-string compare().
    inline int caseCmp(const char *S, const size_type n) const {
        return compare(S,caseInsensitive,n);
    }
    inline int caseCmp(const char *S) const {
        return compare(S,caseInsensitive,npos);
    }

    /** check whether the entire supplied argument is a prefix of the SBuf.
     *  \param S the prefix to match against
     *  \param isCaseSensitive one of caseSensitive or caseInsensitive
     *  \retval true argument is a prefix of the SBuf
     */
    bool startsWith(const SBuf &S, const SBufCaseSensitive isCaseSensitive = caseSensitive) const;

    bool operator ==(const SBuf & S) const;
    bool operator !=(const SBuf & S) const;
    bool operator <(const SBuf &S) const {return (cmp(S) < 0);}
    bool operator >(const SBuf &S) const {return (cmp(S) > 0);}
    bool operator <=(const SBuf &S) const {return (cmp(S) <= 0);}
    bool operator >=(const SBuf &S) const {return (cmp(S) >= 0);}

    /** Consume bytes at the head of the SBuf
     *
     * Consume N chars at SBuf head, or to SBuf's end,
     * whichever is shorter. If more bytes are consumed than available,
     * the SBuf is emptied
     * \param n how many bytes to remove; could be zero.
     *     npos (or no argument) means 'to the end of SBuf'
     * \return a new SBuf containing the consumed bytes.
     */
    SBuf consume(size_type n = npos);

    /// gets global statistic informations
    static const SBufStats& GetStats();

    /** Copy SBuf contents into user-supplied C buffer.
     *
     * Export a copy of the SBuf's contents into the user-supplied
     * buffer, up to the user-supplied-length. No zero-termination is performed
     * \return num the number of actually-copied chars.
     */
    size_type copy(char *dest, size_type n) const;

    /** exports a pointer to the SBuf internal storage.
     * \warning ACCESSING RAW STORAGE IS DANGEROUS!
     *
     * Returns a ead-only pointer to SBuf's content. No terminating null
     * character is appended (use c_str() for that).
     * The returned value points to an internal location whose contents
     * are guaranteed to remain unchanged only until the next call
     * to a non-constant member function of the SBuf object. Such a
     * call may be implicit (e.g., when SBuf is destroyed
     * upon leaving the current context).
     * This is a very UNSAFE way of accessing the data.
     * This call never returns NULL.
     * \see c_str
     * \note the memory management system guarantees that the exported region
     *    of memory will remain valid if the caller keeps holding
     *    a valid reference to the SBuf object and does not write or append to
     *    it. For example:
     * \code
     * SBuf foo("some string");
     * const char *bar = foo.rawContent();
     * doSomething(bar); //safe
     * foo.append(" other string");
     * doSomething(bar); //unsafe
     * \endcode
     */
    const char* rawContent() const;

    /// \returns a buffer suitable for appending at most `anticipatedSize` bytes
    /// The buffer must be used "immediately" because it is invalidated by most
    /// non-constant SBuf method calls, including such calls against other SBuf
    /// objects that just happen to share the same underlying MemBlob storage!
    char *rawAppendStart(size_type anticipatedSize);

    /// Updates SBuf metadata to reflect appending `actualSize` bytes to the
    /// buffer returned by the corresponding rawAppendStart() call. Throws if
    /// rawAppendStart(actualSize) would have returned a different value now.
    /// \param start raw buffer previously returned by rawAppendStart()
    /// \param actualSize the number of appended bytes
    void rawAppendFinish(const char *start, size_type actualSize);

    /** Obtain how much free space is available in the backing store.
     *
     * \note: unless the client just cow()ed, it is not guaranteed that
     *        the free space can be used.
     */
    size_type spaceSize() const { return store_->spaceSize(); }

    /** exports a null-terminated reference to the SBuf internal storage.
     * \warning ACCESSING RAW STORAGE IS DANGEROUS! DO NOT EVER USE
     *  THE RETURNED POINTER FOR WRITING
     *
     * The returned value points to an internal location whose contents
     * are guaranteed to remain unchanged only until the next call
     * to a non-constant member function of the SBuf object. Such a
     * call may be implicit (e.g., when SBuf is destroyed
     * upon leaving the current context).
     * This is a very UNSAFE way of accessing the data.
     * This call never returns NULL.
     * \see rawContent
     * \note the memory management system guarantees that the exported region
     *    of memory will remain valid will remain valid only if the
     *    caller keeps holding a valid reference to the SBuf object and
     *    does not write or append to it
     */
    const char* c_str();

    /// Returns the number of bytes stored in SBuf.
    size_type length() const {return len_;}

    /** Get the length of the SBuf, as a signed integer
     *
     * Compatibility function for printf(3) which requires a signed int
     * \throw std::exception if buffer length does not fit a signed integer
     */
    int plength() const {
        Must(length() <= INT_MAX);
        return static_cast<int>(length());
    }

    /** Check whether the SBuf is empty
     *
     * \return true if length() == 0
     */
    bool isEmpty() const {return (len_==0);}

    /** Request to guarantee the SBuf's free store space.
     *
     * After the reserveSpace request, the SBuf is guaranteed to have at
     * least minSpace bytes of unused backing store following the currently
     * used portion and single ownership of the backing store.
     * \throw std::exception if the user tries to allocate a too big SBuf
     */
    void reserveSpace(size_type minSpace) {
        Must(minSpace <= maxSize);
        Must(length() <= maxSize - minSpace);
        reserveCapacity(length()+minSpace);
    }

    /** Request to guarantee the SBuf's store capacity
     *
     * After this method is called, the SBuf is guaranteed to have at least
     * minCapacity bytes of total buffer size, including the currently-used
     * portion; it is also guaranteed that after this call this SBuf
     * has unique ownership of the underlying memory store.
     * \throw std::exception if the user tries to allocate a too big SBuf
     */
    void reserveCapacity(size_type minCapacity);

    /** Accommodate caller's requirements regarding SBuf's storage if possible.
     *
     * \return spaceSize(), which may be zero
     */
    size_type reserve(const SBufReservationRequirements &requirements);

    /** slicing method
     *
     * Removes SBuf prefix and suffix, leaving a sequence of 'n'
     * bytes starting from position 'pos', first byte is at pos 0.
     * It is an in-place-modifying version of substr.
     * \param pos start sub-stringing from this byte. If it is
     *      npos or it is greater than the SBuf length, the SBuf is cleared and
     *      an empty SBuf is returned.
     * \param n maximum number of bytes of the resulting SBuf.
     *     npos means "to end of SBuf".
     *     if it is 0, the SBuf is cleared and an empty SBuf is returned.
     *     if it overflows the end of the SBuf, it is capped to the end of SBuf
     * \see substr, trim
     */
    SBuf& chop(size_type pos, size_type n = npos);

    /** Remove characters in the toremove set at the beginning, end or both
     *
     * \param toremove characters to be removed. Stops chomping at the first
     *        found char not in the set
     * \param atBeginning if true (default), strips at the beginning of the SBuf
     * \param atEnd if true (default), strips at the end of the SBuf
     */
    SBuf& trim(const SBuf &toRemove, bool atBeginning = true, bool atEnd = true);

    /** Extract a part of the current SBuf.
     *
     * Return a fresh a fresh copy of a portion the current SBuf, which is
     * left untouched. The same parameter convetions apply as for chop.
     * \see trim, chop
     */
    SBuf substr(size_type pos, size_type n = npos) const;

    /** Find first occurrence of character in SBuf
     *
     * Returns the index in the SBuf of the first occurrence of char c.
     * \return npos if the char was not found
     * \param startPos if specified, ignore any occurrences before that position
     *     if startPos is npos or greater than length() npos is always returned
     *     if startPos is less than zero, it is ignored
     */
    size_type find(char c, size_type startPos = 0) const;

    /** Find first occurrence of SBuf in SBuf.
     *
     * Returns the index in the SBuf of the first occurrence of the
     * sequence contained in the str argument.
     * \param startPos if specified, ignore any occurrences before that position
     *     if startPos is npos or greater than length() npos is always returned
     * \return npos if the SBuf was not found
     */
    size_type find(const SBuf & str, size_type startPos = 0) const;

    /** Find last occurrence of character in SBuf
     *
     * Returns the index in the SBuf of the last occurrence of char c.
     * \return npos if the char was not found
     * \param endPos if specified, ignore any occurrences after that position.
     *   if npos or greater than length(), the whole SBuf is considered
     */
    size_type rfind(char c, size_type endPos = npos) const;

    /** Find last occurrence of SBuf in SBuf
     *
     * Returns the index in the SBuf of the last occurrence of the
     * sequence contained in the str argument.
     * \return npos if the sequence  was not found
     * \param endPos if specified, ignore any occurrences after that position
     *   if npos or greater than length(), the whole SBuf is considered
     */
    size_type rfind(const SBuf &str, size_type endPos = npos) const;

    /** Find first occurrence of character of set in SBuf
     *
     * Finds the first occurrence of ANY of the characters in the supplied set in
     * the SBuf.
     * \return npos if no character in the set could be found
     * \param startPos if specified, ignore any occurrences before that position
     *   if npos, then npos is always returned
     *
     * TODO: rename to camelCase
     */
    size_type findFirstOf(const CharacterSet &set, size_type startPos = 0) const;

    /** Find last occurrence of character of set in SBuf
     *
     * Finds the last occurrence of ANY of the characters in the supplied set in
     * the SBuf.
     * \return npos if no character in the set could be found
     * \param endPos if specified, ignore any occurrences after that position
     *   if npos, the entire SBuf is searched
     */
    size_type findLastOf(const CharacterSet &set, size_type endPos = npos) const;

    /** Find first occurrence character NOT in character set
     *
     * \return npos if all characters in the SBuf are from set
     * \param startPos if specified, ignore any occurrences before that position
     *   if npos, then npos is always returned
     *
     * TODO: rename to camelCase
     */
    size_type findFirstNotOf(const CharacterSet &set, size_type startPos = 0) const;

    /** Find last occurrence character NOT in character set
     *
     * \return npos if all characters in the SBuf are from set
     * \param endPos if specified, ignore any occurrences after that position
     *   if npos, then the entire SBuf is searched
     */
    size_type findLastNotOf(const CharacterSet &set, size_type endPos = npos) const;

    /// converts all characters to lower case; \see man tolower(3)
    void toLower();

    /// converts all characters to upper case; \see man toupper(3)
    void toUpper();

    /// std::string export function
    std::string toStdString() const { return std::string(buf(),length()); }

    const_iterator begin() const {
        return const_iterator(*this, 0);
    }

    const_iterator end() const {
        return const_iterator(*this, length());
    }

    const_reverse_iterator rbegin() const {
        return const_reverse_iterator(*this, length());
    }

    const_reverse_iterator rend() const {
        return const_reverse_iterator(*this, 0);
    }

    // TODO: possibly implement erase() similar to std::string's erase
    // TODO: possibly implement a replace() call

    /// SBuf object identifier meant for test cases and debugging.
    /// Does not change when object does, including during assignment.
    const InstanceId<SBuf> id;

private:

    /**
     * Keeps SBuf's MemBlob alive in a blob-destroying context where
     * a seemingly unrelated memory pointer may belong to the same blob.
     * For [an extreme] example, consider: a.append(a).
     * Compared to an SBuf temporary, this class is optimized to
     * preserve blobs only if needed and to reduce debugging noise.
     */
    class Locker
    {
    public:
        Locker(SBuf *parent, const char *otherBuffer) {
            // lock if otherBuffer intersects the parents buffer area
            const MemBlob *blob = parent->store_.getRaw();
            if (blob->mem <= otherBuffer && otherBuffer < (blob->mem + blob->capacity))
                locket = blob;
        }
    private:
        MemBlob::Pointer locket;
    };
    friend class Locker;

    MemBlob::Pointer store_; ///< memory block, possibly shared with other SBufs
    size_type off_ = 0; ///< our content start offset from the beginning of shared store_
    size_type len_ = 0; ///< number of our content bytes in shared store_
    static SBufStats stats; ///< class-wide statistics

    /** obtain prototype store
     *
     * Just-created SBufs all share to the same MemBlob.
     * This call instantiates and returns it.
     */
    static MemBlob::Pointer GetStorePrototype();

    /**
     * obtains a char* to the beginning of this SBuf in memory.
     * \note the obtained string is NOT null-terminated.
     */
    char * buf() const {return (store_->mem+off_);}

    /** returns the pointer to the first char after this SBuf end
     *
     *  No checks are made that the space returned is safe, checking that is
     *  up to the caller.
     */
    char * bufEnd() const {return (store_->mem+off_+len_);}

    /**
     * Try to guesstimate how big a MemBlob to allocate.
     * The result is guarranteed to be to be at least the desired size.
     */
    size_type estimateCapacity(size_type desired) const {return (2*desired);}

    void reAlloc(size_type newsize);

    void cow(size_type minsize = npos);

    void checkAccessBounds(const size_type pos) const { Must(pos < length()); }

    /** Exports a writable pointer to the SBuf internal storage.
     * \warning Use with EXTREME caution, this is a dangerous operation.
     *
     * Returns a pointer to the first unused byte in the SBuf's storage,
     * which can be be used for appending. At least minSize bytes will
     * be available for writing.
     * The returned pointer must not be stored by the caller, as it will
     * be invalidated by the first call to a non-const method call
     * on the SBuf.
     * This call guarantees to never return nullptr.
     * \see reserveSpace
     * \note Unlike reserveSpace(), this method does not guarantee exclusive
     *       buffer ownership. It is instead optimized for a one writer
     *       (appender), many readers scenario by avoiding unnecessary
     *       copying and allocations.
     * \throw std::exception if the user tries to allocate a too big SBuf
     */
    char *rawSpace(size_type minSize);

    /** Low-level append operation
     *
     * Takes as input a contiguous area of memory and appends its contents
     * to the SBuf, taking care of memory management. Does no bounds checking
     * on the supplied memory buffer, it is the duty of the caller to ensure
     * that the supplied area is valid.
     */
    SBuf& lowAppend(const char * memArea, size_type areaSize);
};

/// Named SBuf::reserve() parameters. Defaults ask for and restrict nothing.
class SBufReservationRequirements
{
public:
    typedef SBuf::size_type size_type;

    /*
     * Parameters are listed in the reverse order of importance: Satisfaction of
     * the lower-listed requirements may violate the higher-listed requirements.
     * For example, idealSpace has no effect unless it exceeds minSpace.
     */
    size_type idealSpace = 0; ///< if allocating anyway, provide this much space
    size_type minSpace = 0; ///< allocate [at least this much] if spaceSize() is smaller
    size_type maxCapacity = SBuf::maxSize; ///< do not allocate more than this
    bool allowShared = true; ///< whether sharing our storage with others is OK
};

/// ostream output operator
inline std::ostream &
operator <<(std::ostream& os, const SBuf& S)
{
    return S.print(os);
}

/// Returns a lower-cased copy of its parameter.
inline SBuf
ToUpper(SBuf buf)
{
    buf.toUpper();
    return buf;
}

/// Returns an upper-cased copy of its parameter.
inline SBuf
ToLower(SBuf buf)
{
    buf.toLower();
    return buf;
}

/**
 * Copy an SBuf into a C-string.
 *
 * Guarantees that the output is a c-string of length
 * no more than SBuf::length()+1 by appending a \0 byte
 * to the C-string copy of the SBuf contents.
 *
 * \note The destination c-string memory MUST be of at least
 *       length()+1 bytes.
 *
 * No protection is added to prevent \0 bytes within the string.
 * Unexpectedly short strings are a problem for the receiver
 * to deal with if it cares.
 *
 * Unlike SBuf::c_str() does not alter the SBuf in any way.
 */
inline void
SBufToCstring(char *d, const SBuf &s)
{
    s.copy(d, s.length());
    d[s.length()] = '\0'; // 0-terminate the destination
    debugs(1, DBG_DATA, "built c-string '" << d << "' from " << s);
}

/**
 * Copy an SBuf into a C-string.
 *
 * \see SBufToCstring(char *d, const SBuf &s)
 *
 * \returns A dynamically allocated c-string based on SBuf.
 *          Use xfree() / safe_free() to release the c-string.
 */
inline char *
SBufToCstring(const SBuf &s)
{
    char *d = static_cast<char*>(xmalloc(s.length()+1));
    SBufToCstring(d, s);
    return d;
}

inline
SBufIterator::SBufIterator(const SBuf &s, size_type pos)
    : iter(s.rawContent()+pos)
{}

inline bool
SBufIterator::operator==(const SBufIterator &s) const
{
    // note: maybe the sbuf comparison is unnecessary?
    return iter == s.iter;
}

inline bool
SBufIterator::operator!=(const SBufIterator &s) const
{
    // note: maybe the sbuf comparison is unnecessary?
    return iter != s.iter;
}

#endif /* SQUID_SBUF_H */

