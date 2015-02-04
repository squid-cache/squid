/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef   SQUID_CBDATA_H
#define   SQUID_CBDATA_H

#include "typedefs.h"

/**
 \defgroup CBDATAAPI Callback Data Allocator API
 \ingroup Components
 \par
 *    Squid's extensive use of callback functions makes it very
 *    susceptible to memory access errors. To address this all callback
 *    functions make use of a construct called cbdata. This allows
 *    functions doing callbacks to verify that the caller is still
 *    valid before making the callback.
 *
 \note  cbdata is intended for callback data and is tailored specifically
 *      to make callbacks less dangerous leaving as few windows of errors as
 *      possible. It is not suitable or intended as a generic RefCount
 *      memory allocator.
 *
 *
 \section Examples Examples
 \par
 *  Here you can find some examples on how to use cbdata, and why.
 *
 \subsection AsyncOpWithoutCBDATA Asynchronous operation without cbdata, showing why cbdata is needed
 \par
 *  For a asyncronous operation with callback functions, the normal
 *  sequence of events in programs NOT using cbdata is as follows:
 *
 \code
    // initialization
    type_of_data our_data;
    ...
    our_data = malloc(...);
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(bar, callback_func, our_data);
    ...
    // The asyncronous operation completes and makes the callback
    callback_func(callback_data, ....);
    // Some time later we clean up our data
    free(our_data);
 \endcode
 *
 \par
 *  However, things become more interesting if we want or need
 *  to free the callback_data, or otherwise cancel the callback,
 *  before the operation completes. In constructs like this you
 *  can quite easily end up with having the memory referenced
 *  pointed to by callback_data freed before the callback is invoked
 *  causing a program failure or memory corruption:
 *
 \code
    // initialization
    type_of_data our_data;
    ...
    our_data = malloc(...);
    ...
    // Initiate a asyncronous operation, with our_data as callback_data
    fooOperationStart(bar, callback_func, our_data);
    ...
    // ouch, something bad happened elsewhere.. try to cleanup
    // but the programmer forgot there is a callback pending from
    // fooOperationsStart() (an easy thing to forget when writing code
    // to deal with errors, especially if there may be many different
    // pending operation)
    free(our_data);
    ...
    // The asyncronous operation completes and makes the callback
    callback_func(callback_data, ....);
    // CRASH, the memory pointer to by callback_data is no longer valid
    // at the time of the callback
 \endcode
 *
 \subsection AsyncOpWithCBDATA Asyncronous operation with cbdata
 *
 \par
 *  The callback data allocator lets us do this in a uniform and
 *  safe manner.  The callback data allocator is used to allocate,
 *  track and free memory pool objects used during callback
 *  operations.  Allocated memory is locked while the asyncronous
 *  operation executes elsewhere, and is freed when the operation
 *  completes.  The normal sequence of events is:
 *
 \code
    // initialization
    type_of_data our_data;
    ...
    our_data = cbdataAlloc(type_of_data);
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
    ...
    cbdataFree(our_data);
 \endcode
 *
 \subsection AsynchronousOpCancelledByCBDATA Asynchronous operation cancelled by cbdata
 *
 \par
 *  With this scheme, nothing bad happens if cbdataFree() gets called
 *  before fooOperantionComplete(...).
 *
 \par   Initalization
 \code
    type_of_data our_data;
    ...
    our_data = cbdataAlloc(type_of_data);
 \endcode
 *  Initiate a asyncronous operation, with our_data as callback_data
 \code
    fooOperationStart(..., callback_func, our_data);
 \endcode
 *  do some stuff with it
 \code
    void *local_pointer = cbdataReference(callback_data);
 \endcode
 *  something bad happened elsewhere.. cleanup
 \code
    cbdataFree(our_data);
 \endcode
 *  The asyncronous operation completes and tries to make the callback
 \code
    void *cbdata;
    if (cbdataReferenceValidDone(local_pointer, &amp;cbdata))
        {
 \endcode
 *  won't be called, as the data is no longer valid
 \code
        callback_func(...., cbdata);
    }
 \endcode
 *
 \par
 *  In this case, when cbdataFree() is called before
 *  cbdataReferenceValidDone(), the callback_data gets marked as invalid.
 *  When the callback_data is invalid before executing the callback
 *  function, cbdataReferenceValidDone() will return 0 and
 *  callback_func is never executed.
 *
 \subsection AddingCBDATAType Adding a new cbdata registered type
 *
 \par
 *  To add new module specific data types to the allocator one uses the
 *  macro CBDATA_CLASS() in the class private section, and CBDATA_CLASS_INIT()
 *      or CBDATA_NAMESPACED_CLASS_INIT() in the .cc file.
 *      This creates new(), delete() and toCbdata() methods
 *  definition in class scope. Any allocate calls must be made with
 *      new() and destruction with delete(), they may be called from anywhere.
 */

/**
 *\ingroup CBDATAAPI
 * cbdata types. Similar to the MEM_* types, but managed in cbdata.cc
 * A big difference is that cbdata types are dynamically allocated.
 * Initially only UNKNOWN type is predefined. Other types are added runtime.
 */
typedef int cbdata_type;
static const cbdata_type CBDATA_UNKNOWN = 0;

/// \ingroup CBDATAAPI
void cbdataRegisterWithCacheManager(void);

/**
 * Allocates a new entry of a registered CBDATA type.
 * \deprecated use CBDATA_CLASS() instead
 */
void *cbdataInternalAlloc(cbdata_type type, const char *, int);
/// \deprecated use CBDATA_CLASS() instead
#define cbdataAlloc(type) ((type *)cbdataInternalAlloc(CBDATA_##type,__FILE__,__LINE__))

/**
 * Frees a entry allocated by cbdataAlloc().
 *
 \note  If there are active references to the entry then the entry
 *      will be freed with the last reference is removed. However,
 *      cbdataReferenceValid() will return false for those references.
 * \deprecated use CBDATA_CLASS() instead
 */
void *cbdataInternalFree(void *p, const char *, int);
/// \deprecated use CBDATA_CLASS() instead
#define cbdataFree(var)     do {if (var) {cbdataInternalFree(var,__FILE__,__LINE__); var = NULL;}} while(0)

#if USE_CBDATA_DEBUG
void cbdataInternalLockDbg(const void *p, const char *, int);
#define cbdataInternalLock(a)       cbdataInternalLockDbg(a,__FILE__,__LINE__)

void cbdataInternalUnlockDbg(const void *p, const char *, int);
#define cbdataInternalUnlock(a)     cbdataInternalUnlockDbg(a,__FILE__,__LINE__)

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
 \param var The reference variable. Will be automatically cleared to NULL.
 \param ptr A temporary pointer to the referenced data (if valid).
 */
int cbdataInternalReferenceDoneValid(void **p, void **tp);
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValid((void **)&(var), (ptr))

#endif /* !CBDATA_DEBUG */

/**
 * \param p A cbdata entry reference pointer.
 *
 * \retval 0    A reference is stale. The pointer refers to a entry freed by cbdataFree().
 * \retval true The reference is valid and active.
 */
int cbdataReferenceValid(const void *p);

/// \ingroup CBDATAAPI
cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size, FREE * free_func);

/**
 * This needs to be defined FIRST in the class definition.
 * It plays with private/public states in C++.
 */
#define CBDATA_CLASS(type)  \
    public: \
        void *operator new(size_t size) { \
          assert(size == sizeof(type)); \
          if (!CBDATA_##type) \
                      CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), NULL); \
          return (type *)cbdataInternalAlloc(CBDATA_##type,__FILE__,__LINE__); \
        } \
        void operator delete (void *address) { \
          if (address) cbdataInternalFree(address,__FILE__,__LINE__);\
        } \
                void *toCbdata() { return this; } \
    private: \
    static cbdata_type CBDATA_##type;

/**
 \par
 *    Creates a new reference to a cbdata entry. Used when you need to
 *    store a reference in another structure. The reference can later
 *    be verified for validity by cbdataReferenceValid().
 *
 \param var
 *       The reference variable is a pointer to the entry, in all
 *       aspects identical to the original pointer. But semantically it
 *       is quite different. It is best if the reference is thought of
 *       and handled as a "void *".
 */
#define cbdataReference(var)    (cbdataInternalLock(var), var)

/**
 \ingroup CBDATAAPI
 * Removes a reference created by cbdataReference().
 *
 \param var The reference variable. Will be automatically cleared to NULL.
 */
#define cbdataReferenceDone(var) do {if (var) {cbdataInternalUnlock(var); var = NULL;}} while(0)

/// \ingroup CBDATAAPI
#define CBDATA_CLASS_INIT(type) cbdata_type type::CBDATA_##type = CBDATA_UNKNOWN
#define CBDATA_NAMESPACED_CLASS_INIT(namespace, type) cbdata_type namespace::type::CBDATA_##type = CBDATA_UNKNOWN

/**
 * Macro that defines a new cbdata datatype. Similar to a variable
 * or struct definition. Scope is always local to the file/block
 * where it is defined and all calls to cbdataAlloc() for this type
 * must be within the same scope as the CBDATA_TYPE declaration.
 * Allocated entries may be referenced or freed anywhere with no
 * restrictions on scope.
 * \deprecated Use CBDATA_CLASS() instead
 */
#define CBDATA_TYPE(type)   static cbdata_type CBDATA_##type = CBDATA_UNKNOWN

/**
 \ingroup CBDATAAPI
 *
 * Initializes the cbdatatype. Must be called prior to the first use of cbdataAlloc() for the type.
 *
 \par
 * Alternative to CBDATA_INIT_TYPE()
 *
 \param type        Type being initialized
 \param free_func   The freehandler called when the last known reference to an allocated entry goes away.
 */
#define CBDATA_INIT_TYPE_FREECB(type, free_func) do { if (!CBDATA_##type) CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), free_func); } while (false)

/**
 * Initializes the cbdatatype. Must be called prior to the first use of cbdataAlloc() for the type.
 *
 \par
 * Alternative to CBDATA_INIT_TYPE_FREECB()
 *
 \param type        Type being initialized
 *
 * \deprecated Use CBDATA_CLASS() instead
 */
#define CBDATA_INIT_TYPE(type)  CBDATA_INIT_TYPE_FREECB(type, NULL)

/**
 \ingroup CBDATA
 *
 * A generic wrapper for passing objects through cbdata.
 * Use this when you need to pass callback data to a blocking
 * operation, but you don't want to/cannot have that pointer be cbdata itself.
 */
class generic_cbdata
{
    CBDATA_CLASS(generic_cbdata);

public:

    generic_cbdata(void * aData) : data(aData) {}

    template<typename wrapped_type>void unwrap(wrapped_type **output) {
        *output = static_cast<wrapped_type *>(data);
        delete this;
    }

private:
    /**
     * The wrapped data - only public to allow the mild abuse of this facility
     * done by store_swapout - it gives a wrapped StoreEntry to StoreIO as the
     * object to be given to the callbacks. That needs to be fully cleaned up!
     * - RBC 20060820
     \todo CODE: make this a private field.
     */
    void *data; /* the wrapped data */
};

#endif /* SQUID_CBDATA_H */

