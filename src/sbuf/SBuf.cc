/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/CharacterSet.h"
#include "base/RefCount.h"
#include "Debug.h"
#include "sbuf/DetailedStats.h"
#include "sbuf/SBuf.h"
#include "util.h"

#include <cstring>
#include <functional>
#include <iostream>
#include <sstream>

InstanceIdDefinitions(SBuf, "SBuf");

SBufStats SBuf::stats;
const SBuf::size_type SBuf::npos;
const SBuf::size_type SBuf::maxSize;

SBuf::SBuf() : store_(GetStorePrototype())
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

SBuf::SBuf(const std::string &s) : store_(GetStorePrototype())
{
    debugs(24, 8, id << " created from std::string");
    lowAppend(s.data(),s.length());
    ++stats.alloc;
    ++stats.live;
}

SBuf::SBuf(const char *S, size_type n) : store_(GetStorePrototype())
{
    append(S,n);
    ++stats.alloc;
    ++stats.allocFromCString;
    ++stats.live;
}

SBuf::SBuf(const char *S) : store_(GetStorePrototype())
{
    append(S,npos);
    ++stats.alloc;
    ++stats.allocFromCString;
    ++stats.live;
}

SBuf::~SBuf()
{
    debugs(24, 8, id << " destructed");
    --stats.live;
    recordSBufSizeAtDestruct(len_);
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
    const Locker blobKeeper(this, S);
    debugs(24, 6, id << " from c-string, n=" << n << ")");
    clear();
    return append(S, n); //bounds checked in append()
}

void
SBuf::reserveCapacity(size_type minCapacity)
{
    Must(minCapacity <= maxSize);
    cow(minCapacity);
}

SBuf::size_type
SBuf::reserve(const SBufReservationRequirements &req)
{
    debugs(24, 8, id << " was: " << off_ << '+' << len_ << '+' << spaceSize() <<
           '=' << store_->capacity);

    const bool mustRealloc = !req.allowShared && store_->LockCount() > 1;

    if (!mustRealloc && spaceSize() >= req.minSpace)
        return spaceSize(); // the caller is content with what we have

    /* only reallocation can make the caller happy */

    if (!mustRealloc && len_ >= req.maxCapacity)
        return spaceSize(); // but we cannot reallocate

    const size_type desiredSpace = std::max(req.minSpace, req.idealSpace);
    const size_type newSpace = std::min(desiredSpace, maxSize - len_);
    reserveCapacity(std::min(len_ + newSpace, req.maxCapacity));
    debugs(24, 7, id << " now: " << off_ << '+' << len_ << '+' << spaceSize() <<
           '=' << store_->capacity);
    return spaceSize(); // reallocated and probably reserved enough space
}

char *
SBuf::rawAppendStart(size_type anticipatedSize)
{
    char *space = rawSpace(anticipatedSize);
    debugs(24, 8, id << " start appending up to " << anticipatedSize << " bytes");
    return space;
}

void
SBuf::rawAppendFinish(const char *start, size_type actualSize)
{
    Must(bufEnd() == start);
    Must(store_->canAppend(off_ + len_, actualSize));
    debugs(24, 8, id << " finish appending " << actualSize << " bytes");

    size_type newSize = length() + actualSize;
    Must2(newSize <= min(maxSize,store_->capacity-off_), "raw append overflow");
    len_ = newSize;
    store_->size = off_ + newSize;
}

char *
SBuf::rawSpace(size_type minSpace)
{
    Must(length() <= maxSize - minSpace);
    debugs(24, 7, "reserving " << minSpace << " for " << id);
    ++stats.rawAccess;
    // we're not concerned about RefCounts here,
    // the store knows the last-used portion. If
    // it's available, we're effectively claiming ownership
    // of it. If it's not, we need to go away (realloc)
    if (store_->canAppend(off_+len_, minSpace)) {
        debugs(24, 7, id << " not growing");
        return bufEnd();
    }
    // TODO: we may try to memmove before realloc'ing in order to avoid
    //   one allocation operation, if we're the sole owners of a MemBlob.
    //   Maybe some heuristic on off_ and length()?
    cow(minSpace+length());
    return bufEnd();
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
    if (isEmpty() && store_ == GetStorePrototype())
        return (*this = S); // optimization: avoid needless copying

    const Locker blobKeeper(this, S.buf());
    return lowAppend(S.buf(), S.length());
}

SBuf &
SBuf::append(const char * S, size_type Ssize)
{
    const Locker blobKeeper(this, S);
    if (S == NULL)
        return *this;
    if (Ssize == SBuf::npos)
        Ssize = strlen(S);
    debugs(24, 7, "from c-string to id " << id);
    // coverity[access_dbuff_in_call]
    return lowAppend(S, Ssize);
}

SBuf &
SBuf::append(const char c)
{
    return lowAppend(&c, 1);
}

SBuf&
SBuf::Printf(const char *fmt, ...)
{
    // with printf() the fmt or an arg might be a dangerous char*
    // NP: can't rely on vappendf() Locker because of clear()
    const Locker blobKeeper(this, buf());

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
    // with (v)appendf() the fmt or an arg might be a dangerous char*
    const Locker blobKeeper(this, buf());

    Must(fmt != NULL);
    int sz = 0;
    //reserve twice the format-string size, it's a likely heuristic
    size_type requiredSpaceEstimate = strlen(fmt)*2;

    char *space = rawSpace(requiredSpaceEstimate);
    va_list ap;
    va_copy(ap, vargs);
    sz = vsnprintf(space, spaceSize(), fmt, ap);
    va_end(ap);
    Must2(sz >= 0, "vsnprintf() output error");

    /* check for possible overflow */
    /* snprintf on Linux returns -1 on output errors, or the size
     * that would have been written if enough space had been available */
    /* vsnprintf is standard in C99 */

    if (sz >= static_cast<int>(spaceSize())) {
        // not enough space on the first go, we now know how much we need
        requiredSpaceEstimate = sz*2; // TODO: tune heuristics
        space = rawSpace(requiredSpaceEstimate);
        sz = vsnprintf(space, spaceSize(), fmt, vargs);
        Must2(sz >= 0, "vsnprintf() output error despite increased buffer space");
    }

    // data was appended, update internal state
    len_ += sz;

    /* C99 specifies that the final '\0' is not counted in vsnprintf's
     * return value. Older compilers/libraries might instead count it */
    /* check whether '\0' was appended and counted */
    static bool snPrintfTerminatorChecked = false;
    static bool snPrintfTerminatorCounted = false;
    if (!snPrintfTerminatorChecked) {
        char testbuf[16];
        snPrintfTerminatorCounted = snprintf(testbuf, sizeof(testbuf),
                                             "%s", "1") == 2;
        snPrintfTerminatorChecked = true;
    }
    if (snPrintfTerminatorCounted) {
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
    os << ", offset:" << off_
       << ", len:" << len_
       << ") : '";
    print(os);
    os << '\'' << std::endl;
    return os;
# if 0
    // alternate implementation, based on Raw() API.
    os << Raw("SBuf", buf(), length()) <<
       ". id: " << id <<
       ", offset:" << off_ <<
       ", len:" << len_ <<
       ", store: ";
    store_->dump(os);
    os << std::endl;
    return os;
#endif
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
SBuf::compare(const SBuf &S, const SBufCaseSensitive isCaseSensitive, const size_type n) const
{
    if (n != npos) {
        debugs(24, 8, "length specified. substr and recurse");
        return substr(0,n).compare(S.substr(0,n),isCaseSensitive);
    }

    const size_type byteCompareLen = min(S.length(), length());
    ++stats.compareSlow;
    int rv = 0;
    debugs(24, 8, "comparing length " << byteCompareLen);
    if (isCaseSensitive == caseSensitive) {
        rv = memcmp(buf(), S.buf(), byteCompareLen);
    } else {
        rv = memcasecmp(buf(), S.buf(), byteCompareLen);
    }
    if (rv != 0) {
        debugs(24, 8, "result: " << rv);
        return rv;
    }
    if (n <= length() || n <= S.length()) {
        debugs(24, 8, "same contents and bounded length. Equal");
        return 0;
    }
    if (length() == S.length()) {
        debugs(24, 8, "same contents and same length. Equal");
        return 0;
    }
    if (length() > S.length()) {
        debugs(24, 8, "lhs is longer than rhs. Result is 1");
        return 1;
    }
    debugs(24, 8, "rhs is longer than lhs. Result is -1");
    return -1;
}

int
SBuf::compare(const char *s, const SBufCaseSensitive isCaseSensitive, const size_type n) const
{
    // 0-length comparison is always true regardless of buffer states
    if (!n) {
        ++stats.compareFast;
        return 0;
    }

    // N-length compare MUST provide a non-NULL C-string pointer
    assert(s);

    // when this is a 0-length string, no need for any complexity.
    if (!length()) {
        ++stats.compareFast;
        return '\0' - *s;
    }

    // brute-force scan in order to avoid ever needing strlen() on a c-string.
    ++stats.compareSlow;
    const char *left = buf();
    const char *right = s;
    int rv = 0;
    // what area to scan.
    // n may be npos, but we treat that as a huge positive value
    size_type byteCount = min(length(), n);

    // loop until we find a difference, a '\0', or reach the end of area to scan
    if (isCaseSensitive == caseSensitive) {
        while ((rv = *left - *right++) == 0) {
            if (*left++ == '\0' || --byteCount == 0)
                break;
        }
    } else {
        while ((rv = tolower(*left) - tolower(*right++)) == 0) {
            if (*left++ == '\0' || --byteCount == 0)
                break;
        }
    }

    // If we stopped scanning because we reached the end
    //  of buf() before we reached the end of s,
    // pretend we have a 0-terminator there to compare.
    // NP: the loop already incremented "right" ready for this comparison
    if (!byteCount && length() < n)
        return '\0' - *right;

    // If we found a difference within the scan area,
    // or we found a '\0',
    // or all n characters were identical (and none was \0).
    return rv;
}

bool
SBuf::startsWith(const SBuf &S, const SBufCaseSensitive isCaseSensitive) const
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
    if (n == npos)
        n = length();
    else
        n = min(n, length());
    debugs(24, 8, id << " consume " << n);
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

const char*
SBuf::c_str()
{
    ++stats.rawAccess;
    /* null-terminate the current buffer, by hand-appending a \0 at its tail but
     * without increasing its length. May COW, the side-effect is to guarantee that
     * the MemBlob's tail is available for us to use */
    *rawSpace(1) = '\0';
    ++store_->size;
    ++stats.setChar;
    ++stats.nulTerminate;
    return buf();
}

SBuf&
SBuf::chop(size_type pos, size_type n)
{
    if (pos == npos || pos > length())
        pos = length();

    if (n == npos || (pos+n) > length())
        n = length() - pos;

    // if there will be nothing left, reset the buffer while we can
    if (pos == length() || n == 0) {
        clear();
        return *this;
    }

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

    if (startPos == npos) // can't find anything if we look past end of SBuf
        return npos;

    // std::string returns npos if needle is outside hay
    if (startPos > length())
        return npos;

    const void *i = memchr(buf()+startPos, (int)c, (size_type)length()-startPos);

    if (i == NULL)
        return npos;

    return (static_cast<const char *>(i)-buf());
}

SBuf::size_type
SBuf::find(const SBuf &needle, size_type startPos) const
{
    if (startPos == npos) { // can't find anything if we look past end of SBuf
        ++stats.find;
        return npos;
    }

    // std::string allows needle to overhang hay but not start outside
    if (startPos > length()) {
        ++stats.find;
        return npos;
    }

    // for empty needle std::string returns startPos
    if (needle.length() == 0) {
        ++stats.find;
        return startPos;
    }

    // if needle length is 1 use the char search
    if (needle.length() == 1)
        return find(needle[0], startPos);

    ++stats.find;

    char *start = buf()+startPos;
    char *lastPossible = buf()+length()-needle.length()+1;
    char needleBegin = needle[0];

    debugs(24, 7, "looking for " << needle << "starting at " << startPos <<
           " in id " << id);
    while (start < lastPossible) {
        char *tmp;
        debugs(24, 8, " begin=" << (void *) start <<
               ", lastPossible=" << (void*) lastPossible );
        tmp = static_cast<char *>(memchr(start, needleBegin, lastPossible-start));
        if (tmp == NULL) {
            debugs(24, 8, "First byte not found");
            return npos;
        }
        // lastPossible guarantees no out-of-bounds with memcmp()
        if (0 == memcmp(needle.buf(), tmp, needle.length())) {
            debugs(24, 8, "Found at " << (tmp-buf()));
            return (tmp-buf());
        }
        start = tmp+1;
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

    // needle is bigger than haystack, impossible find
    if (length() < needle.length())
        return npos;

    // if startPos is npos, std::string scans from the end of hay
    if (endPos == npos || endPos > length()-needle.length())
        endPos = length()-needle.length();

    // an empty needle found at the end of the haystack
    if (needle.length() == 0)
        return endPos;

    char *bufBegin = buf();
    char *cur = bufBegin+endPos;
    const char needleBegin = needle[0];
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

    // shortcut: haystack is empty, can't find anything by definition
    if (length() == 0)
        return npos;

    // on npos input std::string compares last octet of hay
    if (endPos == npos || endPos >= length()) {
        endPos = length();
    } else {
        // NP: off-by-one weirdness:
        // endPos is an offset ... 0-based
        // length() is a count ... 1-based
        // memrhr() requires a 1-based count of space to scan.
        ++endPos;
    }

    if (length() == 0)
        return endPos;

    const void *i = memrchr(buf(), (int)c, (size_type)endPos);

    if (i == NULL)
        return npos;

    return (static_cast<const char *>(i)-buf());
}

SBuf::size_type
SBuf::findFirstOf(const CharacterSet &set, size_type startPos) const
{
    ++stats.find;

    if (startPos == npos)
        return npos;

    if (startPos >= length())
        return npos;

    debugs(24, 7, "first of characterset " << set.name << " in id " << id);
    char *cur = buf()+startPos;
    const char *bufend = bufEnd();
    while (cur < bufend) {
        if (set[*cur])
            return cur-buf();
        ++cur;
    }
    debugs(24, 7, "not found");
    return npos;
}

SBuf::size_type
SBuf::findFirstNotOf(const CharacterSet &set, size_type startPos) const
{
    ++stats.find;

    if (startPos == npos)
        return npos;

    if (startPos >= length())
        return npos;

    debugs(24, 7, "first not of characterset " << set.name << " in id " << id);
    char *cur = buf()+startPos;
    const char *bufend = bufEnd();
    while (cur < bufend) {
        if (!set[*cur])
            return cur-buf();
        ++cur;
    }
    debugs(24, 7, "not found");
    return npos;
}

SBuf::size_type
SBuf::findLastOf(const CharacterSet &set, size_type endPos) const
{
    ++stats.find;

    if (isEmpty())
        return npos;

    if (endPos == npos || endPos >= length())
        endPos = length() - 1;

    debugs(24, 7, "last of characterset " << set.name << " in id " << id);
    const char *start = buf();
    for (const char *cur = start + endPos; cur >= start; --cur) {
        if (set[*cur])
            return cur - start;
    }
    debugs(24, 7, "not found");
    return npos;
}

SBuf::size_type
SBuf::findLastNotOf(const CharacterSet &set, size_type endPos) const
{
    ++stats.find;

    if (isEmpty())
        return npos;

    if (endPos == npos || endPos >= length())
        endPos = length() - 1;

    debugs(24, 7, "last not of characterset " << set.name << " in id " << id);
    const char *start = buf();
    for (const char *cur = start + endPos; cur >= start; --cur) {
        if (!set[*cur])
            return cur - start;
    }
    debugs(24, 7, "not found");
    return npos;
}

void
SBuf::toLower()
{
    debugs(24, 8, "\"" << *this << "\"");
    for (size_type j = 0; j < length(); ++j) {
        const int c = (*this)[j];
        if (isupper(c))
            setAt(j, tolower(c));
    }
    debugs(24, 8, "result: \"" << *this << "\"");
    ++stats.caseChange;
}

void
SBuf::toUpper()
{
    debugs(24, 8, "\"" << *this << "\"");
    for (size_type j = 0; j < length(); ++j) {
        const int c = (*this)[j];
        if (islower(c))
            setAt(j, toupper(c));
    }
    debugs(24, 8, "result: \"" << *this << "\"");
    ++stats.caseChange;
}

/** re-allocate the backing store of the SBuf.
 *
 * If there are contents in the SBuf, they will be copied over.
 * NO verifications are made on the size parameters, it's up to the caller to
 * make sure that the new size is big enough to hold the copied contents.
 * The re-allocated storage MAY be bigger than the requested size due to size-chunking
 * algorithms in MemBlock, it is guaranteed NOT to be smaller.
 */
void
SBuf::reAlloc(size_type newsize)
{
    debugs(24, 8, id << " new size: " << newsize);
    Must(newsize <= maxSize);
    MemBlob::Pointer newbuf = new MemBlob(newsize);
    if (length() > 0)
        newbuf->append(buf(), length());
    store_ = newbuf;
    off_ = 0;
    ++stats.cowSlow;
    debugs(24, 7, id << " new store capacity: " << store_->capacity);
}

SBuf&
SBuf::lowAppend(const char * memArea, size_type areaSize)
{
    rawSpace(areaSize); //called method also checks n <= maxSize()
    store_->append(memArea, areaSize);
    len_ += areaSize;
    ++stats.append;
    return *this;
}

/**
 * copy-on-write: make sure that we are the only holder of the backing store.
 * If not, reallocate. If a new size is specified, and it is greater than the
 * current length, the backing store will be extended as needed
 */
void
SBuf::cow(SBuf::size_type newsize)
{
    debugs(24, 8, id << " new size:" << newsize);
    if (newsize == npos || newsize < length())
        newsize = length();

    if (store_->LockCount() == 1 && newsize == length()) {
        debugs(24, 8, id << " no cow needed");
        ++stats.cowFast;
        return;
    }
    reAlloc(newsize);
}

