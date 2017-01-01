/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_GENERIC_H
#define SQUID_GENERIC_H

#include "dlink.h"

#include <ostream>

template <class _Arg, class _Result>
struct unary_function {
    typedef _Arg argument_type;
    typedef _Result result_type;
};

template <class L, class T>
T& for_each(L const &head, T& visitor)
{
    for (L const *node = &head; node; node=node->next)
        visitor(*node);

    return visitor;
}

template <class T>
T& for_each(dlink_list const &collection, T& visitor)
{
    for (dlink_node const *node = collection.head; node; node=node->next)
        visitor(*(typename T::argument_type const *)node->data);

    return visitor;
}

/* RBC 20030718 - use this to provide instance expecting classes a pointer to a
 * singleton
 */

template <class C>
class InstanceToSingletonAdapter : public C
{

public:
    void *operator new (size_t byteCount) { return ::operator new (byteCount);}

    void operator delete (void *address) { ::operator delete (address);}

    InstanceToSingletonAdapter(C const *instance) : theInstance (instance) {}

    C const * operator-> () const {return theInstance; }

    C * operator-> () {return const_cast<C *>(theInstance); }

    C const & operator * () const {return *theInstance; }

    C & operator * () {return *const_cast<C *>(theInstance); }

    operator C const * () const {return theInstance;}

    operator C *() {return const_cast<C *>(theInstance);}

private:
    C const *theInstance;
};

template <class InputIterator , class Visitor>
Visitor& for_each(InputIterator from, InputIterator to, Visitor& visitor)
{
    while (!(from == to)) {
        typename InputIterator::value_type &value = *from;
        ++from;
        visitor(value);
    }

    return visitor;
}

/* generic ostream printer */
template <class Pointer>
struct PointerPrinter {
    PointerPrinter(std::ostream &astream, std::string aDelimiter) : os(astream), delimiter (aDelimiter) {}

    void operator () (Pointer aNode) {
        os << *aNode << delimiter;
    }

    std::ostream &os;
    std::string delimiter;
};

#endif /* SQUID_GENERIC_H */

