/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section --    Refcount allocator */

#ifndef SQUID_REFCOUNT_H_
#define SQUID_REFCOUNT_H_

// reference counting requires the Lock API on base classes
#include "base/Lock.h"

#include <iostream>

/**
 * Template for Reference Counting pointers.
 *
 * Objects of type 'C' must inherit from 'RefCountable' in base/Lock.h
 * which provides the locking interface used by reference counting.
 */
template <class C>
class RefCount
{

public:
    RefCount () : p_ (NULL) {}

    RefCount (C const *p) : p_(p) { reference (*this); }

    ~RefCount() {
        dereference();
    }

    RefCount (const RefCount &p) : p_(p.p_) {
        reference (p);
    }

    RefCount (RefCount &&p) : p_(std::move(p.p_)) {
        p.p_=NULL;
    }

    /// Base::Pointer = Derived::Pointer
    template <class Other>
    RefCount(const RefCount<Other> &p): p_(p.getRaw()) {
        reference(*this);
    }

    RefCount& operator = (const RefCount& p) {
        // DO NOT CHANGE THE ORDER HERE!!!
        // This preserves semantics on self assignment
        C const *newP_ = p.p_;
        reference(p);
        dereference(newP_);
        return *this;
    }

    RefCount& operator = (RefCount&& p) {
        if (this != &p) {
            dereference(p.p_);
            p.p_ = NULL;
        }
        return *this;
    }

    explicit operator bool() const { return p_; }

    bool operator !() const { return !p_; }

    C * operator-> () const {return const_cast<C *>(p_); }

    C & operator * () const {
        assert(p_);
        return *const_cast<C *>(p_);
    }

    C * getRaw() const { return const_cast<C *>(p_); }

    bool operator == (const RefCount& p) const {
        return p.p_ == p_;
    }

    bool operator != (const RefCount &p) const {
        return p.p_ != p_;
    }

private:
    void dereference(C const *newP = NULL) {
        /* Setting p_ first is important:
        * we may be freed ourselves as a result of
        * delete p_;
        */
        C const (*tempP_) (p_);
        p_ = newP;

        if (tempP_ && tempP_->unlock() == 0)
            delete tempP_;
    }

    void reference (const RefCount& p) {
        if (p.p_)
            p.p_->lock();
    }

    C const *p_;

};

template <class C>
inline std::ostream &operator <<(std::ostream &os, const RefCount<C> &p)
{
    if (p != NULL)
        return os << p.getRaw() << '*' << p->LockCount();
    else
        return os << "NULL";
}

#endif /* SQUID_REFCOUNT_H_ */

