/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_ELEMENTLIST_H
#define SQUID_ELEMENTLIST_H

#include "esi/Element.h"

class ElementList
{

public:
    ElementList();
    ~ElementList();

    ESIElement::Pointer &operator[](int);
    ESIElement::Pointer const &operator[](int)const;
    ESIElement::Pointer * elements; /* unprocessed or rendered nodes */
    void pop_front (size_t const);
    void push_back(ESIElement::Pointer &);
    size_t size() const;
    void setNULL (int start, int end);

    int allocedcount;
    size_t allocedsize;
    int elementcount;

private:
    ElementList(ElementList const &);
    ElementList &operator=(ElementList const&);
};

#endif /* SQUID_ELEMENTLIST_H */

