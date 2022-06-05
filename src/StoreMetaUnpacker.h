/*
 * Copyright (C) 1996-2022 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_TYPELENGTHVALUEUNPACKER_H
#define SQUID_TYPELENGTHVALUEUNPACKER_H

#include "StoreMeta.h"

namespace Store {

/// iterates swapped out swap meta fields, loaded into a given buffer
class SwapMetaIterator
{
public:
    /* some of the standard iterator traits */
    using iterator_category = std::forward_iterator_tag;
    using value_type = const SwapMetaView;
    using pointer = value_type *;
    using reference = value_type &;

    /// positions iterator at the start of a swap meta field extending up to end
    SwapMetaIterator(const void *start, const void *end);

    /* some of the standard iterator methods */
    reference operator *() const { return meta_; }
    pointer operator ->() const { return &meta_; }
    SwapMetaIterator& operator++();
    bool operator ==(const SwapMetaIterator &them) const { return fieldStart_ == them.fieldStart_; }
    bool operator !=(const SwapMetaIterator &them) const { return !(*this == them); }

private:
    void sync();

    const char *fieldStart_; ///< the start of the current field
    const void * const bufEnd_; ///< last field must end at this boundary
    SwapMetaView meta_; ///< current field; valid after sync() and before end
};

} // namespace Store

class StoreMetaUnpacker
{

public:
    StoreMetaUnpacker (const char *buf, ssize_t bufferLength, int *hdrlen);

    // for-range loop API for iterating over serialized swap metadata fields
    using Iterator = Store::SwapMetaIterator;
    Iterator cbegin() const { return Iterator(metas, metas + metasSize); }
    Iterator cend() const { return Iterator(metas + metasSize, metas + metasSize); }
    Iterator begin() const { return cbegin(); }
    Iterator end() const { return cend(); }

private:
    const char *metas; ///< metadata field(s)
    size_t metasSize; ///< number of bytes in the metas buffer
};

#endif /* SQUID_TYPELENGTHVALUEUNPACKER_H */

