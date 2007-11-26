/*
 * $Id: Array.h,v 1.25 2007/11/26 13:09:54 hno Exp $
 *
 * AUTHOR: Alex Rousskov
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

#ifndef SQUID_ARRAY_H
#define SQUID_ARRAY_H

#include "fatal.h"
#include "util.h"

/* iterator support */

template <class C>

class VectorIteratorBase
{

public:
    VectorIteratorBase();
    VectorIteratorBase(C &);
    VectorIteratorBase(size_t, C &);
    VectorIteratorBase & operator =(VectorIteratorBase const &);
    bool operator != (VectorIteratorBase const &rhs);
    bool operator == (VectorIteratorBase const &rhs);
    VectorIteratorBase & operator ++();
    VectorIteratorBase operator ++(int);
    typename C::value_type & operator *() const
    {
        return theVector->items[pos];
    }

    typename C::value_type * operator -> () const
    {
        return &theVector->items[pos];
    }

    ssize_t operator - (VectorIteratorBase const &rhs) const;
    bool incrementable() const;

private:
    size_t pos;
    C * theVector;
};

template<class E>

class Vector
{

public:
    typedef E value_type;
    typedef E* pointer;
    typedef VectorIteratorBase<Vector<E> > iterator;
    typedef VectorIteratorBase<Vector<E> const> const_iterator;

    void *operator new (size_t);
    void operator delete (void *);

    Vector();
    ~Vector();
    Vector(Vector const &);
    Vector &operator = (Vector const &);
    void clean();
    void reserve (size_t capacity);
    void push_back (E);
    Vector &operator += (E item) {push_back(item); return *this;};

    void insert (E);
    E &back();
    E pop_back();
    E shift();         // aka pop_front
    void prune(E);
    void preAppend(int app_count);
    bool empty() const;
    size_t size() const;
    iterator begin();
    const_iterator begin () const;
    iterator end();
    const_iterator end () const;
    E& operator [] (unsigned i);

    /* Do not change these, until the entry C struct is removed */
    size_t capacity;
    size_t count;
    E *items;
};

template<class E>
void *
Vector<E>::operator new(size_t size)
{
    return xmalloc (size);
}

template<class E>
void
Vector<E>::operator delete (void *address)
{
    xfree (address);
}

template<class E>
Vector<E>::Vector() : capacity (0), count(0), items (NULL)
{}

template<class E>
Vector<E>::~Vector()
{
    clean();
}

template<class E>
void
Vector<E>::clean()
{
    /* could also warn if some objects are left */
    delete[] items;
    items = NULL;
    capacity = 0;
    count = 0;
}

/* grows internal buffer to satisfy required minimal capacity */
template<class E>
void
Vector<E>::reserve(size_t min_capacity)
{
    const int min_delta = 16;
    int delta;

    if (capacity >= min_capacity)
        return;

    delta = min_capacity;

    /* make delta a multiple of min_delta */
    delta += min_delta - 1;

    delta /= min_delta;

    delta *= min_delta;

    /* actual grow */
    if (delta < 0)
        delta = min_capacity - capacity;

    E*newitems = new E[capacity + delta];

    for (size_t counter = 0; counter < size(); ++counter) {
        newitems[counter] = items[counter];
    }

    capacity += delta;
    delete[]items;
    items = newitems;
}

template<class E>
void
Vector<E>::push_back(E obj)
{
    if (size() >= capacity)
        reserve (size() + 1);

    items[count++] = obj;
}

template<class E>
void
Vector<E>::insert(E obj)
{
    if (size() >= capacity)
        reserve (size() + 1);

    int i;

    for (i = count; i > 0; i--)
        items[i] = items[i - 1];

    items[i] = obj;

    count += 1;
}

template<class E>
E
Vector<E>::shift()
{
    assert (size());
    value_type result = items[0];

    for (unsigned int i = 1; i < count; i++)
        items[i-1] = items[i];

    count--;

    return result;
}

template<class E>
E
Vector<E>::pop_back()
{
    assert (size());
    value_type result = items[--count];
    items[count] = value_type();
    return result;
}

template<class E>
E &
Vector<E>::back()
{
    assert (size());
    return items[size() - 1];
}

template<class E>
void
Vector<E>::prune(E item)
{
    unsigned int n = 0;
    for (unsigned int i = 0; i < count; i++) {
	if (items[i] != item) {
	    if (i != n)
		items[n] = items[i];
	    n++;
	}
    }

    count = n;
}

/* if you are going to append a known and large number of items, call this first */
template<class E>
void
Vector<E>::preAppend(int app_count)
{
    if (size() + app_count > capacity)
        reserve(size() + app_count);
}

template<class E>
Vector<E>::Vector (Vector<E> const &rhs)
{
    items = NULL;
    capacity = 0;
    count = 0;
    reserve (rhs.size());

    for (size_t counter = 0; counter < rhs.size(); ++counter)
        push_back (rhs.items[counter]);
}

template<class E>
Vector<E> &
Vector<E>::operator = (Vector<E> const &old)
{
    clean();
    reserve (old.size());

    for (size_t counter = 0; counter < old.size(); ++counter)
        push_back (old.items[counter]);

    return *this;
}

template<class E>
bool
Vector<E>::empty() const
{
    return size() == 0;
}

template<class E>
size_t
Vector<E>::size() const
{
    return count;
}

template<class E>
typename Vector<E>::iterator
Vector<E>::begin()
{
    return iterator (0, *this);
}

template<class E>
typename Vector<E>::iterator
Vector<E>::end()
{
    return iterator(size(), *this);
}

template<class E>
typename Vector<E>::const_iterator
Vector<E>::begin() const
{
    return const_iterator (0, *this);
}

template<class E>
typename Vector<E>::const_iterator
Vector<E>::end() const
{
    return const_iterator(size(), *this);
}

template<class E>
E &
Vector<E>::operator [] (unsigned i)
{
    assert (size() > i);
    return items[i];
}

template<class C>
VectorIteratorBase<C>::VectorIteratorBase() : pos(0), theVector(NULL)
{}

template<class C>
VectorIteratorBase<C>::VectorIteratorBase(C &container) : pos(container.begin()), theVector(&container)
{}

template<class C>
VectorIteratorBase<C>::VectorIteratorBase(size_t aPos, C &container) : pos(aPos), theVector(&container) {}

template<class C>
bool VectorIteratorBase<C>:: operator != (VectorIteratorBase<C> const &rhs)
{
    assert (theVector);
    return pos != rhs.pos;
}

template<class C>
bool VectorIteratorBase<C>:: operator == (VectorIteratorBase<C> const &rhs)
{
    assert (theVector);
    return pos == rhs.pos;
}

template<class C>
bool
VectorIteratorBase<C>::incrementable() const
{
    assert (theVector);
    return pos != theVector->size();
}

template<class C>
VectorIteratorBase<C> & VectorIteratorBase<C>:: operator ++()
{
    assert (theVector);

    if (!incrementable())
        fatal ("domain error");

    ++pos;

    return *this;
}

template<class C>
VectorIteratorBase<C> VectorIteratorBase<C>:: operator ++(int)
{
    VectorIteratorBase result(*this);
    ++*this;
    return result;
}

template<class C>
VectorIteratorBase<C>&
VectorIteratorBase<C>::operator =(VectorIteratorBase<C> const &old)
{
    pos = old.pos;
    theVector = old.theVector;
    return *this;
}

template<class C>
ssize_t
VectorIteratorBase<C>::operator - (VectorIteratorBase<C> const &rhs) const
{
    assert(theVector == rhs.theVector);
    return pos - rhs.pos;
}

#endif /* SQUID_ARRAY_H */
