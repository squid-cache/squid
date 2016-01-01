/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
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
    CBDATA_CLASS2(CbDataList);
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

/** \cond AUTODOCS_IGNORE */
template <class C>
cbdata_type CbDataList<C>::CBDATA_CbDataList = CBDATA_UNKNOWN;
/** \endcond */

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

