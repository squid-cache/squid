/*
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

#ifndef SQUID_LIST_H
#define SQUID_LIST_H

/** \todo FUBAR: cbdata.h is over in src/ */
#include "../src/cbdata.h"

/// \ingroup POD
template <class C>
class CbDataList
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    CbDataList (C const &);
    ~CbDataList();

    /// If element is already in the list, returns false.
    /// Otherwise, adds the element to the end of the list and returns true.
    /// Exists to avoid double iteration of find() and push() combo.
    bool push_back_unique(C const &element);
    bool find(C const &)const;
    bool findAndTune(C const &);
    /// Iterates the entire list to return the last element holder.
    CbDataList *tail();
    CbDataList *next;
    C element;
    bool empty() const { return this == NULL; }

private:
    CBDATA_CLASS(CbDataList);
};

/// \ingroup POD
template<class C>
class CbDataListContainer
{

public:
    CbDataListContainer();
    ~CbDataListContainer();
    CbDataList<C> *push_back (C const &);
    C pop_front();
    bool empty() const;

    CbDataList<C> *head;
};

/// \ingroup POD
template<class C>
class CbDataListIterator
{
public:
    CbDataListIterator(CbDataListContainer<C> const &list) : next_entry(list.head) {}
    const C & next() {
        CbDataList<C> *entry = next_entry;
        if (entry)
            next_entry = entry->next;
        return entry->element;
    }
    bool end() {
        return next_entry == NULL;
    }

private:
    CbDataList<C> *next_entry;
};

/* implementation follows */

/** \cond AUTODOCS-IGNORE */
template <class C>
cbdata_type CbDataList<C>::CBDATA_CbDataList = CBDATA_UNKNOWN;
/** \endcond */

template <class C>
void *
CbDataList<C>::operator new (size_t byteCount)
{
    CBDATA_INIT_TYPE(CbDataList);

    CbDataList<C> *result = cbdataAlloc(CbDataList);

    return result;
}

template <class C>
void
CbDataList<C>::operator delete (void *address)
{
    cbdataFree(address);
}

template <class C>
CbDataList<C>::CbDataList(C const &value) : next(NULL), element (value)
{}

template <class C>
CbDataList<C>::~CbDataList()
{
    if (next)
        delete next;
}

template <class C>
bool
CbDataList<C>::push_back_unique(C const &toAdd)
{
    CbDataList<C> *last;
    for (last = this; last->next; last = last->next) {
        if (last->element == toAdd)
            return false;
    }

    last->next = new CbDataList<C>(toAdd);
    return true;
}

template <class C>
CbDataList<C> *
CbDataList<C>::tail()
{
    CbDataList<C> *last;
    for (last = this; last->next; last = last->next);
    return last;
}

template <class C>
bool
CbDataList<C>::find (C const &toFind) const
{
    CbDataList<C> const *node = NULL;

    for (node = this; node; node = node->next)
        if (node->element == toFind)
            return true;

    return false;
}

template <class C>
bool
CbDataList<C>::findAndTune(C const & toFind)
{
    CbDataList<C> *prev = NULL;

    for (CbDataList<C> *node = this; node; node = node->
            next) {
        if (node->element == toFind) {
            if (prev != NULL) {
                /* shift the element just found to the second position
                 * in the list */
                prev->next = node->next;
                node->next = this->next;
                this->next = node;
            }

            return true;
        }

        prev = node;
    }

    return false;
}

template <class C>
CbDataListContainer<C>::CbDataListContainer() : head (NULL)
{}

template <class C>
CbDataListContainer<C>::~CbDataListContainer()
{
    if (head)
        delete head;
}

template <class C>
CbDataList<C> *
CbDataListContainer<C>::push_back (C const &element)
{
    CbDataList<C> *node = new CbDataList<C> (element);

    if (head) {
        CbDataList<C> *tempNode = NULL;

        for (tempNode = head; tempNode->next; tempNode = tempNode->next);
        tempNode->next = node;
    } else
        head = node;

    return node;
}

template <class C>
C
CbDataListContainer<C>::pop_front()
{
    if (head) {
        C result = head->element;
        CbDataList<C> *node = head;
        head = head->next;
        node->next = NULL;
        delete node;
        return result;
    }

    return C();
}

template <class C>
bool
CbDataListContainer<C>::empty() const
{
    return head == NULL;
}

#endif /* SQUID_LIST_H */
