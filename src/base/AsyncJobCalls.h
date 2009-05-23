
/*
 * $Id$
 */

#ifndef SQUID_ASYNCJOBCALLS_H
#define SQUID_ASYNCJOBCALLS_H

#include "base/AsyncJob.h"

/*
 * *MemFunT are member function (i.e., class method) wrappers. They store
 * details of a method call in an object so that the call can be delayed
 * and executed asynchronously.  Details may include the object pointer,
 * the handler method pointer, and parameters.  To simplify, we require
 * all handlers to return void and not be constant.
 */

/*
 * We need one wrapper for every supported member function arity (i.e.,
 * number of handler arguments). The first template parameter is the class
 * type of the handler. That class must be an AsyncJob child.
 */

// Arity names are from http://en.wikipedia.org/wiki/Arity

template <class C>
class NullaryMemFunT: public JobDialer
{
public:
    typedef void (C::*Method)();
    explicit NullaryMemFunT(C *anObject, Method aMethod):
            JobDialer(anObject), object(anObject), method(aMethod) {}

    virtual void print(std::ostream &os) const {  os << "()"; }

public:
    C *object;
    Method method;

protected:
    virtual void doDial() { (object->*method)(); }
};

template <class C, class Argument1>
class UnaryMemFunT: public JobDialer
{
public:
    typedef void (C::*Method)(Argument1);
    explicit UnaryMemFunT(C *anObject, Method aMethod, const Argument1 &anArg1):
            JobDialer(anObject),
            object(anObject), method(aMethod), arg1(anArg1) {}

    virtual void print(std::ostream &os) const {  os << '(' << arg1 << ')'; }

public:
    C *object;
    Method method;
    Argument1 arg1;

protected:
    virtual void doDial() { (object->*method)(arg1); }
};

// ... add more as needed


// Now we add global templated functions that create the member function
// wrappers above. These are for convenience: it is often easier to
// call a templated function than to create a templated object.

template <class C>
NullaryMemFunT<C>
MemFun(C *object, typename NullaryMemFunT<C>::Method method)
{
    return NullaryMemFunT<C>(object, method);
}

template <class C, class Argument1>
UnaryMemFunT<C, Argument1>
MemFun(C *object, typename UnaryMemFunT<C, Argument1>::Method method,
       Argument1 arg1)
{
    return UnaryMemFunT<C, Argument1>(object, method, arg1);
}

#endif /* SQUID_ASYNCJOBCALLS_H */
