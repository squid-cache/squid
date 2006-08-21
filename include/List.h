
/*
 * $Id: List.h,v 1.7 2006/08/21 00:50:40 robertc Exp $
 *
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

#ifndef SQUID_LIST_H
#define SQUID_LIST_H

#include "cbdata.h"

template <class C>

class List
{

public:
    void *operator new (size_t);
    void operator delete (void *);
    List (C const &);
    ~List();

    bool find(C const &)const;
    bool findAndTune(C const &);
    List *next;
    C element;
    bool empty() const { return this == NULL; }

private:
    CBDATA_CLASS(List);
};

template<class C>

class ListContainer
{

public:
    ListContainer();
    ~ListContainer();
    List<C> *push_back (C const &);
    C pop_front();
    bool empty() const;

    List<C> *head;
};

template<class C>
class ListIterator
{
public:
    ListIterator(ListContainer<C> const &list) : next_entry(list.head) {}
    const C & next() {
	List<C> *entry = next_entry;
	if (entry)
	    next_entry = entry->next;
	return entry->element;
    }
    bool end() {
	return next_entry == NULL;
    }

private:
    List<C> *next_entry;
};

/* implementation follows */
#if 0
template <class C>
MemPool *List<C>::Pool(NULL);

#endif
template <class C>
cbdata_type List<C>::CBDATA_List = CBDATA_UNKNOWN;

template <class C>
void *
List<C>::operator new (size_t byteCount)
{
    CBDATA_INIT_TYPE(List);

    List<C> *result = cbdataAlloc(List);

    return result;
}

template <class C>
void
List<C>::operator delete (void *address)
{
    cbdataFree(address);
}

template <class C>
List<C>::List(C const &value) : next(NULL), element (value)
{}

template <class C>
List<C>::~List()
{
    if (next)
        delete next;
}

template <class C>
bool
List<C>::find (C const &toFind) const
{
    List<C> const *node = NULL;

    for (node = this; node; node = node->next)
        if (node->element == toFind)
            return true;

    return false;
}

template <class C>
bool
List<C>::findAndTune(C const & toFind)
{
    List<C> *prev = NULL;

    for (List<C> *node = this; node; node = node->
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
ListContainer<C>::ListContainer() : head (NULL)
{}

template <class C>
ListContainer<C>::~ListContainer()
{
    if (head)
        delete head;
}

template <class C>
List<C> *
ListContainer<C>::push_back (C const &element)
{
    List<C> *node = new List<C> (element);

    if (head) {
        List<C> *tempNode = NULL;

        for (tempNode = head; tempNode->next; tempNode = tempNode->next)

            ;
        tempNode->next = node;
    } else
        head = node;

    return node;
}

template <class C>
C
ListContainer<C>::pop_front()
{
    if (head) {
        C result = head->element;
        List<C> *node = head;
        head = head->next;
        node->next = NULL;
        delete node;
        return result;
    }

    return C();
}

template <class C>
bool
ListContainer<C>::empty() const
{
    return head == NULL;
}

#endif /* SQUID_LIST_H */
