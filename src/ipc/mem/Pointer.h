/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_IPC_MEM_POINTER_H
#define SQUID_IPC_MEM_POINTER_H

#include "base/RefCount.h"
#include "base/TextException.h"
#include "ipc/mem/Segment.h"

namespace Ipc
{

namespace Mem
{

/// allocates/deallocates shared memory; creates and later destroys a
/// Class object using that memory
template <class Class>
class Owner
{
public:
    static Owner *New(const char *const id);
    template <class P1>
    static Owner *New(const char *const id, const P1 &p1);
    template <class P1, class P2>
    static Owner *New(const char *const id, const P1 &p1, const P2 &p2);
    template <class P1, class P2, class P3>
    static Owner *New(const char *const id, const P1 &p1, const P2 &p2, const P3 &p3);
    template <class P1, class P2, class P3, class P4>
    static Owner *New(const char *const id, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4);

    ~Owner();

    /// Raw access; handy to finalize initiatization, but avoid if possible.
    Class *object() { return theObject; }

private:
    Owner(const char *const id, const off_t sharedSize);

    // not implemented
    Owner(const Owner &);
    Owner &operator =(const Owner &);

    Segment theSegment; ///< shared memory segment that holds the object
    Class *theObject; ///< shared object
};

template <class Class> class Pointer;

/// attaches to a shared memory segment with Class object owned by Owner
template <class Class>
class Object: public RefCountable
{
public:
    static Pointer<Class> Old(const char *const id);

private:
    explicit Object(const char *const id);

    // not implemented
    Object(const Object &);
    Object &operator =(const Object &);

    Segment theSegment; ///< shared memory segment that holds the object
    Class *theObject; ///< shared object

    friend class Pointer<Class>;
};

/// uses a refcounted pointer to Object<Class> as a parent, but
/// translates its API to return raw Class pointers
template <class Class>
class Pointer: public RefCount< Object<Class> >
{
private:
    typedef RefCount< Object<Class> > Base;

public:
    explicit Pointer(Object<Class> *const anObject = NULL): Base(anObject) {}

    Class *operator ->() const { return Base::operator ->()->theObject; }
    Class &operator *() const { return *Base::operator *().theObject; }
    const Class *getRaw() const { return Base::getRaw()->theObject; }
    Class *getRaw() { return Base::getRaw()->theObject; }
};

// Owner implementation

template <class Class>
Owner<Class>::Owner(const char *const id, const off_t sharedSize):
    theSegment(id), theObject(NULL)
{
    theSegment.create(sharedSize);
    Must(theSegment.mem());
}

template <class Class>
Owner<Class>::~Owner()
{
    if (theObject)
        theObject->~Class();
}

template <class Class>
Owner<Class> *
Owner<Class>::New(const char *const id)
{
    const off_t sharedSize = Class::SharedMemorySize();
    Owner *const owner = new Owner(id, sharedSize);
    owner->theObject = new (owner->theSegment.reserve(sharedSize)) Class;
    return owner;
}

template <class Class> template <class P1>
Owner<Class> *
Owner<Class>::New(const char *const id, const P1 &p1)
{
    const off_t sharedSize = Class::SharedMemorySize(p1);
    Owner *const owner = new Owner(id, sharedSize);
    owner->theObject = new (owner->theSegment.reserve(sharedSize)) Class(p1);
    return owner;
}

template <class Class> template <class P1, class P2>
Owner<Class> *
Owner<Class>::New(const char *const id, const P1 &p1, const P2 &p2)
{
    const off_t sharedSize = Class::SharedMemorySize(p1, p2);
    Owner *const owner = new Owner(id, sharedSize);
    owner->theObject = new (owner->theSegment.reserve(sharedSize)) Class(p1, p2);
    return owner;
}

template <class Class> template <class P1, class P2, class P3>
Owner<Class> *
Owner<Class>::New(const char *const id, const P1 &p1, const P2 &p2, const P3 &p3)
{
    const off_t sharedSize = Class::SharedMemorySize(p1, p2, p3);
    Owner *const owner = new Owner(id, sharedSize);
    owner->theObject = new (owner->theSegment.reserve(sharedSize)) Class(p1, p2, p3);
    return owner;
}

template <class Class> template <class P1, class P2, class P3, class P4>
Owner<Class> *
Owner<Class>::New(const char *const id, const P1 &p1, const P2 &p2, const P3 &p3, const P4 &p4)
{
    const off_t sharedSize = Class::SharedMemorySize(p1, p2, p3, p4);
    Owner *const owner = new Owner(id, sharedSize);
    owner->theObject = new (owner->theSegment.reserve(sharedSize)) Class(p1, p2, p3, p4);
    return owner;
}

// Object implementation

template <class Class>
Object<Class>::Object(const char *const id): theSegment(id)
{
    theSegment.open();
    Must(theSegment.mem());
    theObject = reinterpret_cast<Class*>(theSegment.mem());
    Must(static_cast<off_t>(theObject->sharedMemorySize()) == theSegment.size());
}

template <class Class>
Pointer<Class>
Object<Class>::Old(const char *const id)
{
    return Pointer<Class>(new Object(id));
}

// convenience macros for creating shared objects
#define shm_new(Class) Ipc::Mem::Owner<Class>::New
#define shm_old(Class) Ipc::Mem::Object<Class>::Old

} // namespace Mem

} // namespace Ipc

#endif /* SQUID_IPC_MEM_POINTER_H */

