/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_CBDATA_H
#define SQUID_SRC_CBDATA_H

/**
\page CBDATA Callback Data Allocator API

 \section  Introduction

 \par
   Squid's extensive use of callback functions makes it very
   susceptible to memory access errors. To address this all callback
   functions make use of a construct called cbdata. This allows
   functions doing callbacks to verify that the caller is still
   valid before making the callback.

 \note cbdata is intended for callback data and is tailored specifically
       to make callbacks less dangerous leaving as few windows of errors as
       possible. It is not suitable or intended as a generic RefCount
       memory allocator.

 \par
   The AsyncJob/AsyncCall mechanism is preferred over CBDATA.
   It replaces cbdata with an AsyncCall::Pointer object which
   performs the same memory protection duties via other means.

 \section Examples Examples
 \par
   Here you can find some examples on how to use cbdata, and why.

 \subsection AsyncOpWithoutCBDATA Asynchronous operation without cbdata, showing why cbdata is needed
 \par
   For a asyncronous operation with callback functions, the normal
   sequence of events in programs NOT using cbdata is as follows:

 \code
    // initialization
    type_of_data our_data = new ...;
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(bar, callback_func, our_data);
    ...
    // The asyncronous operation completes and makes the callback
    callback_func(callback_data, ....);
    // Some time later we clean up our data
    delete our_data;
 \endcode

 \par
   However, things become more interesting if we want or need
   to free the callback_data, or otherwise cancel the callback,
   before the operation completes. In constructs like this you
   can quite easily end up with having the memory referenced
   pointed to by callback_data freed before the callback is invoked
   causing a program failure or memory corruption:

 \code
    // initialization
    type_of_data our_data = new ...;
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(bar, callback_func, our_data);
    ...
    // ouch, something bad happened elsewhere.. try to cleanup
    // but the programmer forgot there is a callback pending from
    // fooOperationsStart(). An easy thing to forget when writing code
    // to deal with errors, especially if there may be many different
    // pending operations.
    delete our_data;
    ...
    // The asyncronous operation completes and makes the callback
    callback_func(callback_data, ....);
    // CRASH, the memory pointer to by callback_data is no longer valid
    // at the time of the callback
 \endcode

 \subsection AsyncOpWithCBDATA Asyncronous operation with cbdata

 \par
   The callback data allocator lets us do this in a uniform and
   safe manner.  The callback data allocator is used to allocate,
   track and free memory pool objects used during callback
   operations.  Allocated memory is locked while the asyncronous
   operation executes elsewhere, and is freed when the operation
   completes.  The normal sequence of events is:

 \code
    // initialization
    type_of_data our_data = new type_of_data;
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(..., callback_func, our_data);
    ...
    // foo
    void *local_pointer = cbdataReference(callback_data);
    ....
    // The asyncronous operation completes and makes the callback
    void *cbdata;
    if (cbdataReferenceValidDone(local_pointer, &amp;cbdata))
        callback_func(...., cbdata);
    delete our_data;
 \endcode

 \subsection AsynchronousOpCancelledByCBDATA Asynchronous operation cancelled by cbdata

 \par
   With this scheme, nothing bad happens if delete gets called
   before fooOperantionComplete(...).

 \par   Initalization
 \code
    // initialization
    type_of_data our_data = new type_of_data;
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(..., callback_func, our_data);
    ...
    // do some stuff with it
    void *local_pointer = cbdataReference(callback_data);
    ...
    // something bad happened elsewhere.. cleanup
    delete our_data;
    ....
    // The asyncronous operation completes and makes the callback
    void *cbdata;
    if (cbdataReferenceValidDone(local_pointer, &amp;cbdata))
        // won't be called, as the data is no longer valid
        callback_func(...., cbdata);
    delete our_data;
 \endcode

 \par
   In this case, when delete is called before cbdataReferenceValidDone(),
   the callback_data gets marked as invalid.
   When the callback_data is invalid before executing the callback
   function, cbdataReferenceValidDone() will return 0 and
   callback_func is never executed.

 \subsection AddingCBDATAType Adding a new cbdata registered type

 \par
   To add new module specific data types to the allocator one uses
   the macro CBDATA_CLASS() in the class private section, and
   CBDATA_CLASS_INIT() or CBDATA_NAMESPACED_CLASS_INIT() in the
   class .cc file.

 \code
    class Foo
    {
        CBDATA_CLASS(Foo);

    public:
        Foo() {}
        ~Foo() {}
    };
    ...
    CBDATA_CLASS_INIT(Foo);
 \endcode

 \par
   These macros create new(), delete() and toCbdata() methods
   definition in class scope. Any allocate calls must be made with
   new() and destruction with delete(), they may be called from
   anywhere.

 \par
   The class constructor must make sure that all member
   variables are initialized, and the class destructor that all
   dynamic memory is released.

 \par
   The CbcPointer<> template should be used to create a smart-pointer
   type for simple reference tracking. It provides get() and valid()
   accessors for use instead of cbdataReferenceValid(), and performs
   reliable automatic cbdataReference() and cbdataReferenceDone()
   tracking.
   Note that it does NOT provide a replacement for cbdataReferenceValidDone().

 */

/**
 * cbdata types. Similar to the MEM_* types, but managed in cbdata.cc
 * A big difference is that cbdata types are dynamically allocated.
 *
 * Initially only UNKNOWN type is predefined.
 * Other types are added at runtime by CBDATA_CLASS().
 */
typedef int cbdata_type;
static const cbdata_type CBDATA_UNKNOWN = 0;

/**
 * Create a run-time registration of CBDATA component with
 * the Squid cachemgr
 */
void cbdataRegisterWithCacheManager(void);

/**
 * Allocates a new entry of a registered CBDATA type.
 *
 * \note For internal CBDATA use only.
 */
void *cbdataInternalAlloc(cbdata_type type, const char *, int);

/**
 * Frees a entry allocated by cbdataInternalAlloc().
 *
 * Once this has been called cbdataReferenceValid() and
 * cbdataReferenceValidDone() will return false regardless
 * of whether there are remaining cbdata references.
 *
 * cbdataReferenceDone() must still be called for any active
 * references to the cbdata entry. The cbdata entry will be freed
 * only when the last reference is removed.
 *
 * \note For internal CBDATA use only.
 */
void *cbdataInternalFree(void *p, const char *, int);

#if USE_CBDATA_DEBUG
void cbdataInternalLockDbg(const void *p, const char *, int);
#define cbdataInternalLock(a) cbdataInternalLockDbg(a,__FILE__,__LINE__)

void cbdataInternalUnlockDbg(const void *p, const char *, int);
#define cbdataInternalUnlock(a) cbdataInternalUnlockDbg(a,__FILE__,__LINE__)

int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int);
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValidDbg((void **)&(var), (ptr), __FILE__,__LINE__)

#else
void cbdataInternalLock(const void *p);
void cbdataInternalUnlock(const void *p);

/**
 * Removes a reference created by cbdataReference() and checks
 * it for validity. Meant to be used on the last dereference,
 * usually to make a callback.
 *
 \code
        void *cbdata;
        ...
        if (cbdataReferenceValidDone(reference, &cbdata)) != NULL)
            callback(..., cbdata);
 \endcode
 *
 * \param var The reference variable. Will be automatically cleared to NULL.
 * \param ptr A temporary pointer to the referenced data (if valid).
 */
int cbdataInternalReferenceDoneValid(void **p, void **tp);
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValid((void **)&(var), (ptr))

#endif /* !CBDATA_DEBUG */

/**
 * \param p A cbdata entry reference pointer.
 *
 * \retval 0    A reference is stale. The pointer refers to a entry already freed.
 * \retval true The reference is valid and active.
 */
int cbdataReferenceValid(const void *p);

/**
 * Create a run-time registration for the class type with cbdata memory allocator.
 *
 * \note For internal CBDATA use only.
 */
cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size);

/// declaration-generator used internally by CBDATA_CLASS() and CBDATA_CHILD()
#define CBDATA_DECL_(type, methodSpecifiers) \
    public: \
        void *operator new(size_t size) { \
          assert(size == sizeof(type)); \
          if (!CBDATA_##type) CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type)); \
          return (type *)cbdataInternalAlloc(CBDATA_##type,__FILE__,__LINE__); \
        } \
        void operator delete (void *address) { \
          if (address) cbdataInternalFree(address,__FILE__,__LINE__); \
        } \
        void *toCbdata() methodSpecifiers { return this; } \
    private: \
       static cbdata_type CBDATA_##type;

/// Starts cbdata-protection in a class hierarchy.
/// Child classes in the same hierarchy should use CBDATA_CHILD().
class CbdataParent
{
public:
    virtual ~CbdataParent() {}
    virtual void *toCbdata() = 0;
};

/// cbdata-enables a stand-alone class that is not a CbdataParent child
/// sets the class declaration section to "private"
/// use this at the start of your class declaration for consistency sake
#define CBDATA_CLASS(type) CBDATA_DECL_(type, noexcept)

/// cbdata-enables a CbdataParent child class (including grandchildren)
/// sets the class declaration section to "private"
/// use this at the start of your class declaration for consistency sake
#define CBDATA_CHILD(type) CBDATA_DECL_(type, override final)

/**
 * Creates a global instance pointer for the CBDATA memory allocator
 * to allocate and free objects for the matching CBDATA_CLASS().
 *
 * Place this in the appropriate .cc file for the class being registered.
 *
 * May be placed inside an explicit namespace scope declaration,
 * or CBDATA_NAMESPACED_CLASS_INIT() used instead.
 */
#define CBDATA_CLASS_INIT(type) cbdata_type type::CBDATA_##type = CBDATA_UNKNOWN

/**
 * Creates a global instance pointer for the CBDATA memory allocator
 * to allocate and free objects for the matching CBDATA_CLASS().
 *
 * Place this in the appropriate .cc file for the class being registered.
 */
#define CBDATA_NAMESPACED_CLASS_INIT(namespace, type) cbdata_type namespace::type::CBDATA_##type = CBDATA_UNKNOWN

/**
 * Creates a new reference to a cbdata entry. Used when you need to
 * store a reference in another structure. The reference can later
 * be verified for validity by cbdataReferenceValid().
 *
 * \deprecated Prefer the use of CbcPointer<> smart pointer.
 *
 * \param var
 *       The reference variable is a pointer to the entry, in all
 *       aspects identical to the original pointer. But semantically it
 *       is quite different. It is best if the reference is thought of
 *       and handled as a "void *".
 */
#define cbdataReference(var)    (cbdataInternalLock(var), var)

/**
 * Removes a reference created by cbdataReference().
 *
 * \deprecated Prefer the use of CbcPointer<> smart pointer.
 *
 * \param var The reference variable. Will be automatically cleared to NULL.
 */
#define cbdataReferenceDone(var) do {if (var) {cbdataInternalUnlock(var); var = NULL;}} while(0)

/**
 * A generic wrapper for passing object pointers through cbdata.
 * Use this when you need to pass callback data to a blocking
 * operation, but you don't want to/cannot have that pointer be
 * cbdata itself.
 */
class generic_cbdata
{
    CBDATA_CLASS(generic_cbdata);

public:
    generic_cbdata(void *aData) : data(aData) {}

    template<typename wrapped_type>void unwrap(wrapped_type **output) {
        *output = static_cast<wrapped_type *>(data);
        delete this;
    }

private:
    void *data;
};

#endif /* SQUID_CBDATA_H */

