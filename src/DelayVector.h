/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYVECTOR_H
#define SQUID_DELAYVECTOR_H

#if USE_DELAY_POOLS

#include "base/forward.h"
#include "CompositePoolNode.h"

/// \ingroup DelayPoolsAPI
class DelayVector : public CompositePoolNode
{
    MEMPROXY_CLASS(DelayVector);

public:
    typedef RefCount<DelayVector> Pointer;
    DelayVector();
    ~DelayVector() override;
    void stats(StoreEntry * sentry) override;
    void dump(StoreEntry *entry) const override;
    void update(int incr) override;
    void parse() override;

    DelayIdComposite::Pointer id(CompositeSelectionDetails &) override;
    void push_back (CompositePoolNode::Pointer);

private:

    /// \ingroup DelayPoolsInternal
    class Id:public DelayIdComposite
    {
        MEMPROXY_CLASS(DelayVector::Id);

    public:
        Id (RefCount<DelayVector>,CompositeSelectionDetails &);
        ~Id() override;
        int bytesWanted (int min, int max) const override;
        void bytesIn(int qty) override;
        void delayRead(const AsyncCallPointer &) override;

    private:
        RefCount<DelayVector> theVector;
        std::vector<DelayIdComposite::Pointer> ids;
        typedef std::vector<DelayIdComposite::Pointer>::iterator iterator;
        typedef std::vector<DelayIdComposite::Pointer>::const_iterator const_iterator;
    };

    friend class Id;

    std::vector<CompositePoolNode::Pointer> pools;
    typedef std::vector<CompositePoolNode::Pointer>::iterator iterator;
    typedef std::vector<CompositePoolNode::Pointer>::const_iterator const_iterator;
};

#endif /* USE_DELAY_POOLS */
#endif /* SQUID_DELAYVECTOR_H */

