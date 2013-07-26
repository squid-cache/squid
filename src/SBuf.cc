/*
 * SBuf.cc (C) 2008 Francesco Chemolli <kinkie@squid-cache.org>
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 */

#include "squid.h"
#include "base/RefCount.h"
#include "Debug.h"
#include "OutOfBoundsException.h"
#include "SBuf.h"
#include "SBufExceptions.h"
#include "util.h"

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_SSTREAM
#include <sstream>
#endif

#if HAVE_IOSTREAM
#include <iostream>
#endif

#ifdef VA_COPY
#undef VA_COPY
#endif
#if defined HAVE_VA_COPY
#define VA_COPY va_copy
#elif defined HAVE___VA_COPY
#define VA_COPY __va_copy
#endif

InstanceIdDefinitions(SBuf, "SBuf");

SBufStats SBuf::stats;
const SBuf::size_type SBuf::npos;
const SBuf::size_type SBuf::maxSize;

SBufStats::SBufStats()
        : alloc(0), allocCopy(0), allocFromString(0), allocFromCString(0),
        assignFast(0), clear(0), append(0), toStream(0), setChar(0),
        getChar(0), compareSlow(0), compareFast(0), copyOut(0),
        rawAccess(0), chop(0), trim(0), find(0), scanf(0),
        caseChange(0), cowFast(0), cowSlow(0), live(0)
{}

SBufStats&
SBufStats::operator +=(const SBufStats& ss)
{
    alloc += ss.alloc;
    allocCopy += ss.allocCopy;
    allocFromString += ss.allocFromString;
    allocFromCString += ss.allocFromCString;
    assignFast += ss.assignFast;
    clear += ss.clear;
    append += ss.append;
    toStream += ss.toStream;
    setChar += ss.setChar;
    getChar += ss.getChar;
    compareSlow += ss.compareSlow;
    compareFast += ss.compareFast;
    copyOut += ss.copyOut;
    rawAccess += ss.rawAccess;
    chop += ss.chop;
    trim += ss.trim;
    find += ss.find;
    scanf += ss.scanf;
    caseChange += ss.caseChange;
    cowFast += ss.cowFast;
    cowSlow += ss.cowSlow;
    live += ss.live;

    return *this;
}

SBuf::SBuf()
        : store_(GetStorePrototype()), off_(0), len_(0)
{
    debugs(24, 8, id << " created");
    ++stats.alloc;
    ++stats.live;
}

SBuf::SBuf(const SBuf &S)
        : store_(S.store_), off_(S.off_), len_(S.len_)
{
    debugs(24, 8, id << " created from id " << S.id);
    ++stats.alloc;
    ++stats.allocCopy;
    ++stats.live;
}

SBuf::SBuf(const String &S)
        : store_(GetStorePrototype()), off_(0), len_(0)
{
    debugs(24, 8, id << " created from string");
    assign(S.rawBuf(), S.size());
    ++stats.alloc;
    ++stats.allocFromString;
    ++stats.live;
}

SBuf::SBuf(const std::string &s)
        : store_(GetStorePrototype()), off_(0), len_(0)
{
    debugs(24, 8, id << " created from std::string");
    lowAppend(s.data(),s.length());
    ++stats.alloc;
    ++stats.allocFromString;
    ++stats.live;
}

SBuf::SBuf(const char *S, size_type n)
        : store_(GetStorePrototype()), off_(0), len_(0)
{
    append(S,n);
    ++stats.alloc;
    ++stats.allocFromCString;
    ++stats.live;
}

SBuf::~SBuf()
{
    debugs(24, 8, id << " destructed");
    --stats.live;
}

MemBlob::Pointer
SBuf::GetStorePrototype()
{
    static MemBlob::Pointer InitialStore = new MemBlob(0);
    return InitialStore;
}

SBuf&
SBuf::assign(const SBuf &S)
{
    debugs(24, 7, "assigning " << id << " from " <<  S.id);
    if (&S == this) //assignment to self. Noop.
        return *this;
    ++stats.assignFast;
    store_ = S.store_;
    off_ = S.off_;
    len_ = S.len_;
    return *this;
}

SBuf&
SBuf::assign(const char *S, size_type n)
{
    debugs(24, 6, id << " from c-string, n=" << n << ")");
    clear();
    return append(S, n); //bounds checked in append()
}

void
SBuf::reserveCapacity(size_type minCapacity)
{
    Must(0 <= minCapacity); //upper bound checked in cow -> reAlloc
    cow(minCapacity);
}

void
SBuf::reserveSpace(size_type minSpace)
{
    Must(0 <= minSpace); //upper bound checked in cow -> reAlloc
    debugs(24, 7, "reserving " << minSpace << " for " << id);
    // we're not concerned about RefCounts here,
    // the store knows the last-used portion. If
    // it's available, we're effectively claiming ownership
    // of it. If it's not, we need to go away (realloc)
    if (store_->canAppend(off_+len_, minSpace)) {
        debugs(24, 7, "not growing");
        return;
    }
    // TODO: we may try to memmove before realloc'ing in order to avoid
    //   one allocation operation, if we're the sole owners of a MemBlob.
    //   Maybe some heuristic on off_ and length()?
    reAlloc(estimateCapacity(minSpace+length()));
}

void
SBuf::clear()
{
#if 0
    //enabling this code path, the store will be freed and reinitialized
    store_ = GetStorePrototype(); //uncomment to actually free storage upon clear()
#else
    //enabling this code path, we try to release the store without deallocating it.
    // will be lazily reallocated if needed.
    if (store_->LockCount() == 1)
        store_->clear();
#endif
    len_ = 0;
    off_ = 0;
    ++stats.clear;
}

SBuf&
SBuf::append(const SBuf &S)
{
    return lowAppend(S.buf(), S.length());
}

SBuf &
SBuf::append(const char * S, size_type Ssize)
{
    Must (Ssize == npos || Ssize >= 0);

    if (S == NULL)
        return *this;
    if (Ssize == npos)
        Ssize = strlen(S);
    debugs(24, 7, "from c-string to id " << id);
    return lowAppend(S, Ssize);
}

SBuf&
SBuf::Printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    clear();
    vappendf(fmt, args);
    va_end(args);
    return *this;
}

SBuf&
SBuf::appendf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vappendf(fmt, args);
    va_end(args);
    return *this;
}

SBuf&
SBuf::vappendf(const char *fmt, va_list vargs)
{
#ifdef VA_COPY
    va_list ap;
#endif
    int sz = 0;

    Must(fmt != NULL);

    //reserve twice the format-string size, it's a likely heuristic
    reserveSpace(strlen(fmt)*2);

    while (length() <= maxSize) {
#ifdef VA_COPY
        /* Fix of bug 753r. The value of vargs is undefined
         * after vsnprintf() returns. Make a copy of vargs
         * in case we loop around and call vsnprintf() again.
         */
        VA_COPY(ap, vargs);
        sz = vsnprintf(bufEnd(), store_->spaceSize(), fmt, ap);
        va_end(ap);
#else /* VA_COPY */
        sz = vsnprintf(bufEnd(), store_->spaceSize(), fmt, vargs);
#endif /* VA_COPY*/
        /* check for possible overflow */
        /* snprintf on Linux returns -1 on overflows */
        /* snprintf on FreeBSD returns at least free_space on overflows */

        if (sz >= static_cast<int>(store_->spaceSize()))
            reserveSpace(sz*2); // TODO: tune heuristics
        else if (sz < 0) // output error in vsnprintf
            throw TextException("output error in vsnprintf",__FILE__, __LINE__);
        else
            break;
    }

    len_ += sz;
    // TODO: this does NOT belong here, but to class-init or autoconf
    /* on Linux and FreeBSD, '\0' is not counted in return value */
    /* on XXX it might be counted */
    /* check that '\0' is appended and not counted */

    if (operator[](len_-1) == '\0') {
        --sz;
        --len_;
    }

    store_->size += sz;
    ++stats.append;

    return *this;
}

std::ostream&
SBuf::print(std::ostream &os) const
{
    os.write(buf(), length());
    ++stats.toStream;
    return os;
}

std::ostream&
SBuf::dump(std::ostream &os) const
{
    os << id
    << ": ";
    store_->dump(os);
    os << ",offset:" << off_
    << ",len:" << len_
    << ") : '";
    print(os);
    os << '\'' << std::endl;
    return os;
}

void
SBuf::setAt(size_type pos, char toset)
{
    checkAccessBounds(pos);
    cow();
    store_->mem[off_+pos] = toset;
    ++stats.setChar;
}

static int
memcasecmp(const char *b1, const char *b2, SBuf::size_type len)
{
    int rv=0;
    while (len > 0) {
        rv = tolower(*b1)-tolower(*b2);
        if (rv != 0)
            return rv;
        ++b1;
        ++b2;
        --len;
    }
    return rv;
}

int
SBuf::compare(const SBuf &S, SBufCaseSensitive isCaseSensitive, size_type n) const
{
    Must(n == npos || n >= 0);
    if (n != npos) {
        if (n > length())
            return compare(S.substr(0,n),isCaseSensitive);
        return substr(0,n).compare(S.substr(0,n),isCaseSensitive);
    }
    size_type byteCompareLen = min(S.length(), length());
    ++stats.compareSlow;
    int rv = 0;
    if (isCaseSensitive == caseSensitive) {
        rv = memcmp(buf(), S.buf(), byteCompareLen);
    } else {
        rv = memcasecmp(buf(), S.buf(), byteCompareLen);
    }
    if (rv != 0)
        return rv;
    if (length() == S.length())
        return 0;
    if (length() > S.length())
        return 1;
    return -1;
}

bool
SBuf::startsWith(const SBuf &S, SBufCaseSensitive isCaseSensitive) const
{
    debugs(24, 8, id << " startsWith " << S.id << ", caseSensitive: " <<
           isCaseSensitive);
    if (length() < S.length()) {
        debugs(24, 8, "no, too short");
        ++stats.compareFast;
        return false;
    }
    return (compare(S, isCaseSensitive, S.length()) == 0);
}

bool
SBuf::operator ==(const SBuf & S) const
{
    debugs(24, 8, id << " == " << S.id);
    if (length() != S.length()) {
        debugs(24, 8, "no, different lengths");
        ++stats.compareFast;
        return false; //shortcut: must be equal length
    }
    if (store_ == S.store_ && off_ == S.off_) {
        debugs(24, 8, "yes, same length and backing store");
        ++stats.compareFast;
        return true;  //shortcut: same store, offset and length
    }
    ++stats.compareSlow;
    const bool rv = (0 == memcmp(buf(), S.buf(), length()));
    debugs(24, 8, "returning " << rv);
    return rv;
}

bool
SBuf::operator !=(const SBuf & S) const
{
    return !(*this == S);
}

SBuf
SBuf::consume(size_type n)
{
    Must (n == npos || n >= 0);
    if (n == npos)
        n = length();
    else
        n = min(n, length());
    SBuf rv(substr(0, n));
    chop(n);
    return rv;
}

const
SBufStats& SBuf::GetStats()
{
    return stats;
}

SBuf::size_type
SBuf::copy(char *dest, size_type n) const
{
    Must(n >= 0);

    size_type toexport = min(n,length());
    memcpy(dest, buf(), toexport);
    ++stats.copyOut;
    return toexport;
}

const char*
SBuf::rawContent() const
{
    ++stats.rawAccess;
    return buf();
}

char *
SBuf::rawSpace(size_type minSize)
{
    cow(minSize+length());
    ++stats.rawAccess;
    return bufEnd();
}

void
SBuf::forceSize(size_type newSize)
{
    Must(store_->LockCount() == 1);
    if (newSize > min(maxSize,store_->capacity-off_))
        throw SBufTooBigException(__FILE__,__LINE__);
    len_ = newSize;
    store_->size = newSize;
}

const char*
SBuf::c_str()
{
    ++stats.rawAccess;
    /* null-terminate the current buffer, by hand-appending a \0 at its tail but
     * without increasing its length. May COW, the side-effect is to guarantee that
     * the MemBlob's tail is availabe for us to use */
    *rawSpace(1) = '\0';
    ++store_->size;
    ++stats.setChar;
    return buf();
}

SBuf&
SBuf::chop(size_type pos, size_type n)
{
    if (pos != npos && pos < 0)
        pos = 0;
    if (n != npos && n < 0)
        n = npos;
    if (pos == npos || pos > length() || n == 0) {
        clear();
        return *this;
    }
    if (n == npos || (pos+n) > length())
        n = length()-pos;
    ++stats.chop;
    off_ += pos;
    len_ = n;
    return *this;
}

SBuf&
SBuf::trim(const SBuf &toRemove, bool atBeginning, bool atEnd)
{
    ++stats.trim;
    if (atEnd) {
        const char *p = bufEnd()-1;
        while (!isEmpty() && memchr(toRemove.buf(), *p, toRemove.length()) != NULL) {
            //current end-of-buf is in the searched set
            --len_;
            --p;
        }
    }
    if (atBeginning) {
        const char *p = buf();
        while (!isEmpty() && memchr(toRemove.buf(), *p, toRemove.length()) != NULL) {
            --len_;
            ++off_;
            ++p;
        }
    }
    if (isEmpty())
        clear();
    return *this;
}

SBuf
SBuf::substr(size_type pos, size_type n) const
{
    SBuf rv(*this);
    rv.chop(pos, n); //stats handled by callee
    return rv;
}

SBuf::size_type
SBuf::find(char c, size_type startPos) const
{
    ++stats.find;

    // for npos with char sd::string returns npos
    // this differs from how std::string handles 1-length string
    if (startPos == npos)
        return npos;

    // std::string returns npos if needle is outside hay
    if (startPos >= length())
        return npos;

    // ignore invalid startPos
    if (startPos < 0)
        startPos = 0;

    const void *i = memchr(buf()+startPos, (int)c, (size_type)length()-startPos);

    if (i == NULL)
        return npos;

    return (static_cast<const char *>(i)-buf());
}

SBuf::size_type
SBuf::find(const SBuf &needle, size_type startPos) const
{
    // std::string allows needle to overhang hay but not start outside
    if (startPos != npos && startPos > length()) {
        ++stats.find;
        return npos;
    }

    // for empty needle std::string returns startPos
    if (needle.length() == 0) {
        ++stats.find;
        return startPos;
    }

    // for npos with char* std::string scans entire hay
    // this differs from how std::string handles single char from npos
    if (startPos == npos)
        return npos;

    // if needle length is 1 use the char search
    if (needle.length() == 1)
        return find(needle[0], startPos);

    ++stats.find;

    char *begin = buf()+startPos;
    char *lastPossible = buf()+length()-needle.length()+1;
    char needleBegin = needle[0];

    debugs(24, 7, "looking for " << needle << "starting at " << startPos <<
                    " in id " << id);
    while (begin < lastPossible) {
        char *tmp;
        debugs(24, 8, " begin=" << (void *) begin <<
               ", lastPossible=" << (void*) lastPossible );
        tmp = static_cast<char *>(memchr(begin, needleBegin, lastPossible-begin));
        if (tmp == NULL) {
            debugs(24, 8 , "First byte not found");
            return npos;
        }
        // lastPossible guarrantees no out-of-bounds with memcmp()
        if (0 == memcmp(needle.buf(), tmp, needle.length())) {
            debugs(24, 8, "Found at " << (tmp-buf()));
            return (tmp-buf());
        }
        begin = tmp+1;
    }
    debugs(24, 8, "not found");
    return npos;
}

SBuf::size_type
SBuf::rfind(const SBuf &needle, SBuf::size_type endPos) const
{
    // when the needle is 1 char, use the 1-char rfind()
    if (needle.length() == 1)
        return rfind(needle[0], endPos);

    ++stats.find;

    // on npos input std::string scans from the end of hay
    if (endPos == npos || endPos > length())
        endPos=length();

    // on empty hay std::string returns npos
    if (length() < needle.length())
        return npos;

    // on empty needle std::string returns the position the search starts
    if (needle.length() == 0)
        return endPos;

/* std::string permits needle to overhang endPos
    if (endPos <= needle.length())
        return npos;
*/

    char *bufBegin = buf();
    char *cur = bufBegin+endPos;
    char needleBegin = needle[0];
    while (cur >= bufBegin) {
        if (*cur == needleBegin) {
            if (0 == memcmp(needle.buf(), cur, needle.length())) {
                // found
                return (cur-buf());
            }
        }
        --cur;
    }
    return npos;
}

SBuf::size_type
SBuf::rfind(char c, SBuf::size_type endPos) const
{
    ++stats.find;

    // on empty hay std::string returns size of hay
    if (length() == 0)
        return npos;

    // on npos input std::string compares last octet of hay
    if (endPos == npos || endPos >= length()) {
        endPos = length();
    } else if (endPos < 0) {
        return npos;
    } else {
        // NP: off-by-one weirdness:
        // endPos is an offset ... 0-based
        // length() is a count ... 1-based
        // memrhr() requires a 1-based count of space to scan.
        ++endPos;
    }

    const void *i = memrchr(buf(), (int)c, (size_type)endPos);

    if (i == NULL)
        return npos;

    return (static_cast<const char *>(i)-buf());
}

SBuf::size_type
SBuf::find_first_of(const SBuf &set, size_type startPos) const
{
    // if set is 1 char big, use the char search. Stats updated there
    if (set.length() == 1)
        return find(set[0], startPos);

    ++stats.find;

    if (startPos == npos)
        return npos;

    if (startPos > length())
        return npos;

    if (startPos < 0)
        startPos = 0;

    if (set.length() == 0)
        return npos;

    debugs(24, 7, "any of '" << set << "' " << " in id " << id);
    char *cur = buf()+startPos, *end = bufEnd();
    while (cur < end) {
        if (memchr(set.buf(), *cur, set.length()))
            return (cur-buf());
        ++cur;
    }
    debugs(24, 7, "not found");
    return npos;
}

/*
 * TODO: borrow a sscanf implementation from Linux or similar?
 * we'd really need a vsnscanf(3)... ? As an alternative, a
 * light-regexp-like domain-specific syntax might be an idea.
 */
int
SBuf::scanf(const char *format, ...)
{
    va_list arg;
    int rv;
    ++stats.scanf;
    va_start(arg, format);
    rv = vsscanf(c_str(), format, arg);
    va_end(arg);
    return rv;
}

std::ostream &
SBufStats::dump(std::ostream& os) const
{
    MemBlobStats ststats = MemBlob::GetStats();
    os <<
    "SBuf stats:\nnumber of allocations: " << alloc <<
    "\ncopy-allocations: " << allocCopy <<
    "\ncopy-allocations from SquidString: " << allocFromString <<
    "\ncopy-allocations from C String: " << allocFromCString <<
    "\nlive references: " << live <<
    "\nno-copy assignments: " << assignFast <<
    "\nclearing operations: " << clear <<
    "\nappend operations: " << append <<
    "\ndump-to-ostream: " << toStream <<
    "\nset-char: " << setChar <<
    "\nget-char: " << getChar <<
    "\ncomparisons with data-scan: " << compareSlow <<
    "\ncomparisons not requiring data-scan: " << compareFast <<
    "\ncopy-out ops: " << copyOut <<
    "\nraw access to memory: " << rawAccess <<
    "\nchop operations: " << chop <<
    "\ntrim operations: " << trim <<
    "\nfind: " << find <<
    "\nscanf: " << scanf <<
    "\ncase-change ops: " << caseChange <<
    "\nCOW not actually requiring a copy: " << cowFast <<
    "\nCOW: " << cowSlow <<
    "\naverage store share factor: " <<
    (ststats.live != 0 ? static_cast<float>(live)/ststats.live : 0) <<
    std::endl;
    return os;
}

SBuf
SBuf::toLower() const
{
    debugs(24, 8, "\"" << *this << "\"");
    SBuf rv(*this);
    for (size_type j = 0; j < length(); ++j) {
        const int c = (*this)[j];
        if (isupper(c))
            rv.setAt(j, tolower(c)); //will cow() if needed
    }
    debugs(24, 8, "result: \"" << *this << "\"");
    ++stats.caseChange;
    return rv;
}

SBuf
SBuf::toUpper() const
{
    debugs(24, 8, "\"" << *this << "\"");
    SBuf rv(*this);
    for (size_type j = 0; j < length(); ++j) {
        const int c = (*this)[j];
        if (islower(c))
            rv.setAt(j, toupper(c)); //will cow() if needed
    }
    debugs(24, 8, "result: \"" << *this << "\"");
    ++stats.caseChange;
    return rv;
}

/**
 * checks whether the requested 'pos' is within the bounds of the SBuf
 * \throw OutOfBoundsException if access is out of bounds
 */
void
SBuf::checkAccessBounds(size_type pos) const
{
    if (pos < 0)
        throw OutOfBoundsException(*this, pos, __FILE__, __LINE__);
    if (pos >= length())
        throw OutOfBoundsException(*this, pos, __FILE__, __LINE__);
}

String
SBuf::toString() const
{
    String rv;
    rv.limitInit(buf(), length());
    ++stats.copyOut;
    return rv;
}

/** re-allocate the backing store of the SBuf.
 *
 * If there are contents in the SBuf, they will be copied over.
 * NO verifications are made on the size parameters, it's up to the caller to
 * make sure that the new size is big enough to hold the copied contents.
 * The re-allocated storage MAY be bigger than the requested size due to size-chunking
 * algorithms in MemBlock, it is guarranteed NOT to be smaller.
 */
void
SBuf::reAlloc(size_type newsize)
{
    debugs(24, DBG_DATA, "new size: " << newsize);
    if (newsize > maxSize)
        throw SBufTooBigException(__FILE__, __LINE__);
    MemBlob::Pointer newbuf = new MemBlob(newsize);
    if (length() > 0)
        newbuf->append(buf(), length());
    store_ = newbuf;
    off_ = 0;
    ++stats.cowSlow;
    debugs(24, 7, "new store capacity: " << store_->capacity);
}

SBuf&
SBuf::lowAppend(const char * memArea, size_type areaSize)
{
    reserveSpace(areaSize); //called method also checks n <= maxSize()
    store_->append(memArea, areaSize);
    len_ += areaSize;
    ++stats.append;
    return *this;
}

/**
 * copy-on-write: make sure that we are the only holder of the backing store.
 * If not, reallocate. If a new size is specified, and it is greater than the
 * current length, the backing store will be extended as needed
 * \retval false no grow was needed
 * \retval true had to copy
 */
bool
SBuf::cow(SBuf::size_type newsize)
{
    debugs(24, DBG_DATA, "new size:" << newsize);
    if (newsize == npos || newsize < length())
        newsize = length();

    if (store_->LockCount() == 1 && newsize == length()) {
        debugs(24, DBG_DATA, "no cow needed");
        ++stats.cowFast;
        return false;
    }
    reAlloc(newsize);
    return true;
}
