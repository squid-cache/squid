/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_ACL_SPLAYINSERTER_H
#define SQUID_SRC_ACL_SPLAYINSERTER_H

#include "acl/Acl.h"
#include "debug/Stream.h"
#include "globals.h"
#include "splay.h"

namespace Acl {

/// Helps populate a Splay tree with configured ACL parameter values and their
/// duplicate-handling derivatives (each represented by a DataValue object).
template <class DataValue>
class SplayInserter
{
public:
    using Value = DataValue;

    /// If necessary, updates the splay tree to match all individual values that
    /// match the given parsed ACL parameter value. If the given value itself is
    /// not added to the tree (e.g., because it is a duplicate), it is destroyed
    /// using DestroyValue(). Otherwise, the given value will be destroyed
    /// later, during subsequent calls to this method or free_acl().
    static void Merge(Splay<Value> &, Value &&);

private:
    /// SplayInserter users are expected to specialize all or most of the static
    /// methods below. Most of these methods have no generic implementation.

    /// whether the set of values matched by `a` contains the entire set of
    /// values matched by `b`, including cases where `a` is identical to `b`
    static bool AcontainsEntireB(const Value &a, const Value &b);

    /// Creates a new Value that matches all individual values matched by `a`
    /// and all individual values matched by `b` but no other values.
    /// \prec the two sets of values matched by `a` and `b` overlap
    static Value MakeCombinedValue(const Value &a, const Value &b);

    /// A Splay::SPLAYCMP function for comparing parsed ACL parameter values.
    /// This function must work correctly with all valid ACL parameter values,
    /// including those representing sets or ranges. The order specified by this
    /// function must be the same as the order specified by the SPLAYCMP
    /// function used later by ACL::match().
    static int Compare(const Value &, const Value &);

    /// A Splay::SPLAYFREE-like function that destroys parsed ACL parameter values.
    static void DestroyValue(Value v) { delete v; }
};

} // namespace Acl

template <class DataValue>
void
Acl::SplayInserter<DataValue>::Merge(Splay<Value> &storage, Value &&newItem)
{
    const auto comparator = &SplayInserter<Value>::Compare;
    while (const auto oldItemPointer = storage.insert(newItem, comparator)) {
        const auto oldItem = *oldItemPointer;
        assert(oldItem);

        if (AcontainsEntireB(oldItem, newItem)) {
            debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Ignoring " << newItem << " because it is already covered by " << oldItem <<
                   Debug::Extra << "advice: Remove value " << newItem << " from the ACL named " << AclMatchedName);
            DestroyValue(newItem);
            return;
        }

        if (AcontainsEntireB(newItem, oldItem)) {
            debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Ignoring earlier " << oldItem << " because it is covered by " << newItem <<
                   Debug::Extra << "advice: Remove value " << oldItem << " from the ACL named " << AclMatchedName);
            storage.remove(oldItem, comparator);
            DestroyValue(oldItem);
            continue; // still need to insert newItem (and it may conflict with other old items)
        }

        const auto combinedItem = MakeCombinedValue(oldItem, newItem);
        debugs(28, DBG_PARSE_NOTE(DBG_IMPORTANT), "WARNING: Merging overlapping " << newItem << " and " << oldItem << " into " << combinedItem <<
               Debug::Extra << "advice: Replace values " << newItem << " and " << oldItem << " with " << combinedItem << " in the ACL named " << AclMatchedName);
        DestroyValue(newItem);
        newItem = combinedItem;
        storage.remove(oldItem, comparator);
        DestroyValue(oldItem);
        continue; // still need to insert updated newItem (and it may conflict with other old items)
    }
}

#endif /* SQUID_SRC_ACL_SPLAYINSERTER_H */

