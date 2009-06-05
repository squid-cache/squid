/*
 * $Id$
 *
 * DEBUG: none          Refcount allocator
 * AUTHOR:  Robert Collins
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
 *
 */

#ifndef _SQUID_REFCOUNT_H_
#define _SQUID_REFCOUNT_H_

#include "config.h"

#if HAVE_IOSTREAM
#include <iostream>
#endif

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

    RefCount& operator = (const RefCount& p) {
        // DO NOT CHANGE THE ORDER HERE!!!
        // This preserves semantics on self assignment
        C const *newP_ = p.p_;
        reference(p);
        dereference(newP_);
        return *this;
    }

    bool operator !() const { return !p_; }

    C const * operator-> () const {return p_; }

    C * operator-> () {return const_cast<C *>(p_); }

    C const & operator * () const {return *p_; }

    C & operator * () {return *const_cast<C *>(p_); }

    C const * getRaw() const {return p_; }

    C * getRaw() {return const_cast<C *>(p_); }

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

        if (tempP_ && tempP_->RefCountDereference() == 0)
            delete tempP_;
    }

    void reference (const RefCount& p) {
        if (p.p_)
            p.p_->RefCountReference();
    }

    C const *p_;

};

struct RefCountable_ {
    RefCountable_():count_(0) {}

    virtual ~RefCountable_() {}

    /* Not private, to allow class hierarchies */
    void RefCountReference() const {
#if REFCOUNT_DEBUG
        debug (0,1)("Incrementing this %p from count %u\n",this,count_);
#endif

        ++count_;
    }

    unsigned RefCountDereference() const {
#if REFCOUNT_DEBUG
        debug (0,1)("Decrementing this %p from count %u\n",this,count_);
#endif

        return --count_;
    }

    unsigned RefCountCount() const { return count_; } // for debugging only

private:
    mutable unsigned count_;
};

#define RefCountable virtual RefCountable_

template <class C>
inline std::ostream &operator <<(std::ostream &os, const RefCount<C> &p)
{
    if (p != NULL)
        return os << p.getRaw() << '*' << p->RefCountCount();
    else
        return os << "NULL";
}

#endif /* _SQUID_REFCOUNT_H_ */
