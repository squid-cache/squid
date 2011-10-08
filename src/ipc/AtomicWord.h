/*
 * $Id$
 *
 */

#ifndef SQUID_IPC_ATOMIC_WORD_H
#define SQUID_IPC_ATOMIC_WORD_H

#if HAVE_ATOMIC_OPS
/// Supplies atomic operations for an integral Value in memory shared by kids.
/// Used to implement non-blocking shared locks, queues, tables, and pools.
template <class ValueType>
class AtomicWordT
{
public:
    typedef ValueType Value;

    AtomicWordT() {} // leave value unchanged
    AtomicWordT(Value aValue): value(aValue) {} // XXX: unsafe

    Value operator +=(int delta) { return __sync_add_and_fetch(&value, delta); }
    Value operator -=(int delta) { return __sync_sub_and_fetch(&value, delta); }
    Value operator ++() { return *this += 1; }
    Value operator --() { return *this -= 1; }
    Value operator ++(int) { return __sync_fetch_and_add(&value, 1); }
    Value operator --(int) { return __sync_fetch_and_sub(&value, 1); }

    bool swap_if(const int comparand, const int replacement) { return __sync_bool_compare_and_swap(&value, comparand, replacement); }

    /// v1 = value; value &= v2; return v1;
    Value fetchAndAnd(const Value v2) { return __sync_fetch_and_and(&value, v2); }

    // TODO: no need for __sync_bool_compare_and_swap here?
    bool operator ==(int v2) { return __sync_bool_compare_and_swap(&value, v2, value); }

    // TODO: no need for __sync_fetch_and_add here?
    Value get() const { return __sync_fetch_and_add(const_cast<Value*>(&value), 0); }
    operator Value () const { return get(); }

private:
    Value value;
};

enum { AtomicOperationsSupported = 1 };

#else
/// A wrapper to provide AtomicWordT API (and asserting implementation)
/// where we do not support atomic operations. This avoids ifdefs in core code.
template <class ValueType>
class AtomicWordT
{
public:
    typedef ValueType Value;

    AtomicWordT() {} // leave value unchanged
    AtomicWordT(Value aValue): value(aValue) {} // XXX: unsafe

    Value operator +=(int) { assert(false); return *this; }
    Value operator ++() { return *this += 1; }
    Value operator --() { return *this += -1; }
    Value operator ++(int) { assert(false); return *this; }
    Value operator --(int) { assert(false); return *this; }

    bool swap_if(const int comparand, const int replacement)
    { assert(false); return false; }

    /// v1 = value; value &= v2; return v1;
    Value fetchAndAnd(const Value v2)
    { assert(false); return value; }

    // TODO: no need for __sync_bool_compare_and_swap here?
    bool operator ==(int v2) { assert(false); return false; }

    // TODO: no need for __sync_fetch_and_add here?
    Value get() const { assert(false); return value; }
    operator Value () const { return get(); }

private:
    Value value;
};

enum { AtomicOperationsSupported = 0 };

#endif /* HAVE_ATOMIC_OPS */

typedef AtomicWordT<int> AtomicWord;

#endif // SQUID_IPC_ATOMIC_WORD_H
