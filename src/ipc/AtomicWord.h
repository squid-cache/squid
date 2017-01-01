/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_ATOMIC_WORD_H
#define SQUID_IPC_ATOMIC_WORD_H

namespace Ipc
{

namespace Atomic
{

/// Whether atomic operations support is available
bool Enabled();

#if HAVE_ATOMIC_OPS

/// Supplies atomic operations for an integral Value in memory shared by kids.
/// Used to implement non-blocking shared locks, queues, tables, and pools.
template <class ValueType>
class WordT
{
public:
    typedef ValueType Value;

    WordT() {} // leave value unchanged
    WordT(Value aValue): value(aValue) {} // XXX: unsafe

    Value operator +=(int delta) { return __sync_add_and_fetch(&value, delta); }
    Value operator -=(int delta) { return __sync_sub_and_fetch(&value, delta); }
    Value operator ++() { return *this += 1; }
    Value operator --() { return *this -= 1; }
    Value operator ++(int) { return __sync_fetch_and_add(&value, 1); }
    Value operator --(int) { return __sync_fetch_and_sub(&value, 1); }

    bool swap_if(const Value comparand, const Value replacement) { return __sync_bool_compare_and_swap(&value, comparand, replacement); }

    /// v1 = value; value &= v2; return v1;
    Value fetchAndAnd(const Value v2) { return __sync_fetch_and_and(&value, v2); }

    // TODO: no need for __sync_bool_compare_and_swap here?
    bool operator ==(const Value v2) { return __sync_bool_compare_and_swap(&value, v2, value); }

    // TODO: no need for __sync_fetch_and_add here?
    Value get() const { return __sync_fetch_and_add(const_cast<Value*>(&value), 0); }
    operator Value () const { return get(); }

private:

    Value value;
};

#else

/// A wrapper to provide AtomicWordT API (and implementation asserting in SMP mode)
/// where we do not support atomic operations. This avoids ifdefs in core code.
template <class ValueType>
class WordT
{
public:
    typedef ValueType Value;

    WordT() {} // leave value unchanged
    WordT(Value aValue): value(aValue) {} // XXX: unsafe

    Value operator +=(int delta) { assert(Enabled()); return value += delta; }
    Value operator ++() { return *this += 1; }
    Value operator --() { return *this += -1; }
    Value operator ++(int) { assert(Enabled()); return value++; }
    Value operator --(int) { assert(Enabled()); return value--; }

    bool swap_if(const Value comparand, const Value replacement)
    { assert(Enabled()); return value == comparand ? value = replacement, true : false; }

    /// v1 = value; value &= v2; return v1;
    Value fetchAndAnd(const Value v2)
    { assert(Enabled()); const Value v1 = value; value &= v2; return v1; }

    // TODO: no need for __sync_bool_compare_and_swap here?
    bool operator ==(const Value v2) { assert(Enabled()); return value == v2; }

    // TODO: no need for __sync_fetch_and_add here?
    Value get() const { assert(Enabled()); return value; }
    operator Value () const { return get(); }

private:

    Value value;
};

#endif /* HAVE_ATOMIC_OPS */

typedef WordT<int> Word;

} // namespace Atomic

} // namespace Ipc

#endif // SQUID_IPC_ATOMIC_WORD_H

