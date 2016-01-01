/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_DELAYVECTOR_H
#define SQUID_DELAYVECTOR_H

#if USE_DELAY_POOLS

#include "CompositePoolNode.h"

/// \ingroup DelayPoolsAPI
class DelayVector : public CompositePoolNode
{

public:
    typedef RefCount<DelayVector> Pointer;
    void *operator new(size_t);
    void operator delete (void *);
    DelayVector();
    virtual ~DelayVector();
    virtual void stats(StoreEntry * sentry);
    virtual void dump(StoreEntry *entry) const;
    virtual void update(int incr);
    virtual void parse();

    virtual DelayIdComposite::Pointer id(CompositeSelectionDetails &);
    void push_back (CompositePoolNode::Pointer);

private:

    /// \ingroup DelayPoolsInternal
    class Id:public DelayIdComposite
    {

    public:
        void *operator new(size_t);
        void operator delete (void *);

        Id (RefCount<DelayVector>,CompositeSelectionDetails &);
        ~Id();
        virtual int bytesWanted (int min, int max) const;
        virtual void bytesIn(int qty);
        virtual void delayRead(DeferredRead const &);

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

