/*
 * $Id$
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
 * Copyright (c) 2003, Robert Collins <robertc@squid-cache.org>
 */

#ifndef   SQUID_CBDATA_H
#define   SQUID_CBDATA_H

#include "squid.h"

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
 \todo CODE: make cbdata a template or class-inheritance system instead of Macros.
 *
 \section Examples Examples
 \par
 *	Here you can find some examples on how to use cbdata, and why.
 *
 \subsection AsyncOpWithoutCBDATA Asynchronous operation without cbdata, showing why cbdata is needed
 \par
 *	For a asyncronous operation with callback functions, the normal
 *	sequence of events in programs NOT using cbdata is as follows:
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
 *	However, things become more interesting if we want or need
 *	to free the callback_data, or otherwise cancel the callback,
 *	before the operation completes. In constructs like this you
 *	can quite easily end up with having the memory referenced
 *	pointed to by callback_data freed before the callback is invoked
 *	causing a program failure or memory corruption:
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
 *	The callback data allocator lets us do this in a uniform and
 *	safe manner.  The callback data allocator is used to allocate,
 *	track and free memory pool objects used during callback
 *	operations.  Allocated memory is locked while the asyncronous
 *	operation executes elsewhere, and is freed when the operation
 *	completes.  The normal sequence of events is:
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
 *	With this scheme, nothing bad happens if cbdataFree() gets called
 *	before fooOperantionComplete(...).
 *
 \par	Initalization
 \code
	type_of_data our_data;
	...
	our_data = cbdataAlloc(type_of_data);
 \endcode
 *	Initiate a asyncronous operation, with our_data as callback_data
 \code
	fooOperationStart(..., callback_func, our_data);
 \endcode
 *	do some stuff with it
 \code
	void *local_pointer = cbdataReference(callback_data);
 \endcode
 *	something bad happened elsewhere.. cleanup
 \code
	cbdataFree(our_data);
 \endcode
 *	The asyncronous operation completes and tries to make the callback
 \code
	void *cbdata;
	if (cbdataReferenceValidDone(local_pointer, &amp;cbdata))
        {
 \endcode
 *	won't be called, as the data is no longer valid
 \code
	    callback_func(...., cbdata);
	}
 \endcode
 *
 \par
 *	In this case, when cbdataFree() is called before
 *	cbdataReferenceValidDone(), the callback_data gets marked as invalid.
 *	When the callback_data is invalid before executing the callback
 *	function, cbdataReferenceValidDone() will return 0 and
 *	callback_func is never executed.
 *
 \subsection AddingCBDATAType Adding a new cbdata registered type
 *
 \par
 *	To add new module specific data types to the allocator one uses the
 *	macros CBDATA_TYPE() and CBDATA_INIT_TYPE(). These creates a local cbdata
 *	definition (file or block scope). Any cbdataAlloc() calls must be made
 *	within this scope. However, cbdataFree() might be called from anywhere.
 *
 \par
 *	First the cbdata type needs to be defined in the module. This
 *	is usually done at file scope, but it can also be local to a
 *	function or block..
 \code
	CBDATA_TYPE(type_of_data);
 \endcode
 *	Then in the code somewhere before the first allocation
 *	(can be called multiple times with only a minimal overhead)
 \code
	CBDATA_INIT_TYPE(type_of_data);
 \endcode
 *	Or if a free function is associated with the data type. This
 *	function is responsible for cleaning up any dependencies etc
 *	referenced by the structure and is called on cbdataFree() or
 *	when the last reference is deleted by cbdataReferenceDone() /
 *	cbdataReferenceValidDone()
 \code
	CBDATA_INIT_TYPE_FREECB(type_of_data, free_function);
 \endcode
 *
 \subsection AddingGlobalCBDATATypes Adding a new cbdata registered data type globally
 *
 \par
 *	To add new global data types that can be allocated from anywhere
 *	within the code one have to add them to the cbdata_type enum in
 *	enums.h, and a corresponding CREATE_CBDATA() call in
 *	cbdata.c:cbdataInit(). Or alternatively add a CBDATA_GLOBAL_TYPE()
 *	definition to globals.h as shown below and use CBDATA_INIT_TYPE() at
 *	the appropriate location(s) as described above.
 *
 \code
	extern CBDATA_GLOBAL_TYPE(type_of_data);	// CBDATA_UNDEF
 \endcode
 */

/**
 *\ingroup CBDATAAPI
 * cbdata types. similar to the MEM_* types above, but managed
 * in cbdata.c. A big difference is that these types are dynamically
 * allocated. This list is only a list of predefined types. Other types
 * are added runtime
 */
typedef enum {
    CBDATA_UNKNOWN = 0
} cbdata_type;

/// \ingroup CBDATAAPI
extern void cbdataRegisterWithCacheManager(void);

#if CBDATA_DEBUG
extern void *cbdataInternalAllocDbg(cbdata_type type, const char *, int);
extern void *cbdataInternalFreeDbg(void *p, const char *, int);
extern void cbdataInternalLockDbg(const void *p, const char *, int);
extern void cbdataInternalUnlockDbg(const void *p, const char *, int);
extern int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int);
#else

/// \ingroup CBDATAAPI
extern void *cbdataInternalAlloc(cbdata_type type);

/// \ingroup CBDATAAPI
extern void *cbdataInternalFree(void *p);

/// \ingroup CBDATAAPI
extern void cbdataInternalLock(const void *p);

/// \ingroup CBDATAAPI
extern void cbdataInternalUnlock(const void *p);

/// \ingroup CBDATAAPI
extern int cbdataInternalReferenceDoneValid(void **p, void **tp);

#endif /* !CBDATA_DEBUG */

/**
 \ingroup CBDATAAPI
 *
 \param p	A cbdata entry reference pointer.
 *
 \retval 0	A reference is stale. The pointer refers to a entry freed by cbdataFree().
 \retval true	The reference is valid and active.
 */
extern int cbdataReferenceValid(const void *p);

/// \ingroup CBDATAAPI
extern cbdata_type cbdataInternalAddType(cbdata_type type, const char *label, int size, FREE * free_func);


/* cbdata macros */
#if CBDATA_DEBUG
#define cbdataAlloc(type)	((type *)cbdataInternalAllocDbg(CBDATA_##type,__FILE__,__LINE__))
#define cbdataFree(var)		do {if (var) {cbdataInternalFreeDbg(var,__FILE__,__LINE__); var = NULL;}} while(0)
#define cbdataInternalLock(a)		cbdataInternalLockDbg(a,__FILE__,__LINE__)
#define cbdataInternalUnlock(a)		cbdataInternalUnlockDbg(a,__FILE__,__LINE__)
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValidDbg((void **)&(var), (ptr), __FILE__,__LINE__)
#define CBDATA_CLASS2(type)	\
	static cbdata_type CBDATA_##type; \
	public: \
		void *operator new(size_t size) { \
		  assert(size == sizeof(type)); \
		  (CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), NULL))); \
		  return cbdataInternalAllocDbg(CBDATA_##type,__FILE__,__LINE__); \
		} \
  		void operator delete (void *address) { \
		  if (address) cbdataInternalFreeDbg(address,__FILE__,__LINE__); \
		} \
                void *toCbdata() { return this; } \
	private:
#else

/**
 \ingroup CBDATAAPI
 * Allocates a new entry of a registered CBDATA type.
 */
#define cbdataAlloc(type) ((type *)cbdataInternalAlloc(CBDATA_##type))

/**
 \ingroup CBDATAAPI
 \par
 *    Frees a entry allocated by cbdataAlloc().
 *
 \note  If there are active references to the entry then the entry
 *      will be freed with the last reference is removed. However,
 *      cbdataReferenceValid() will return false for those references.
 */
#define cbdataFree(var)		do {if (var) {cbdataInternalFree(var); var = NULL;}} while(0)

/**
 \ingroup CBDATAAPI
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
 \param var	The reference variable. Will be automatically cleared to NULL.
 \param ptr	A temporary pointer to the referenced data (if valid).
 */
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValid((void **)&(var), (ptr))

/// \ingroup CBDATAAPI
#define CBDATA_CLASS2(type)	\
	static cbdata_type CBDATA_##type; \
	public: \
		void *operator new(size_t size) { \
		  assert(size == sizeof(type)); \
		  (CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), NULL))); \
		  return (type *)cbdataInternalAlloc(CBDATA_##type); \
		} \
  		void operator delete (void *address) { \
		  if (address) cbdataInternalFree(address);\
		} \
                void *toCbdata() { return this; } \
	private:
#endif /* !CBDATA_DEBUG */

/**
 \ingroup CBDATAAPI
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
#define cbdataReference(var)	(cbdataInternalLock(var), var)

/**
 \ingroup CBDATAAPI
 * Removes a reference created by cbdataReference().
 *
 \param var	The reference variable. Will be automatically cleared to NULL.
 */
#define cbdataReferenceDone(var) do {if (var) {cbdataInternalUnlock(var); var = NULL;}} while(0)

/// \ingroup CBDATAAPI
#define CBDATA_CLASS(type)	static cbdata_type CBDATA_##type

/// \ingroup CBDATAAPI
#define CBDATA_CLASS_INIT(type) cbdata_type type::CBDATA_##type = CBDATA_UNKNOWN
#define CBDATA_NAMESPACED_CLASS_INIT(namespace, type) cbdata_type namespace::type::CBDATA_##type = CBDATA_UNKNOWN

/**
 \ingroup CBDATAAPI
 * Macro that defines a new cbdata datatype. Similar to a variable
 * or struct definition. Scope is always local to the file/block
 * where it is defined and all calls to cbdataAlloc() for this type
 * must be within the same scope as the CBDATA_TYPE declaration.
 * Allocated entries may be referenced or freed anywhere with no
 * restrictions on scope.
 */
#define CBDATA_TYPE(type)	static cbdata_type CBDATA_##type = CBDATA_UNKNOWN

/**
 \ingroup CBDATAAPI
 * Defines a global cbdata type that can be referenced anywhere in the code.
 *
 \code
        external CBDATA_GLOBAL_TYPE(datatype);
 \endcode
 * Should be added to the module *.h header file.
 *
 \code
        CBDATA_GLOBAL_TYPE(datatype);
 \endcode
 *
 *  Should be added to the module main *.cc file.
 */
#define CBDATA_GLOBAL_TYPE(type)	cbdata_type CBDATA_##type

/**
 \ingroup CBDATAAPI
 *
 * Initializes the cbdatatype. Must be called prior to the first use of cbdataAlloc() for the type.
 *
 \par
 * Alternative to CBDATA_INIT_TYPE_FREECB()
 *
 \param type		Type being initialized
 */
#define CBDATA_INIT_TYPE(type)	(CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), NULL)))

/**
 \ingroup CBDATAAPI
 *
 * Initializes the cbdatatype. Must be called prior to the first use of cbdataAlloc() for the type.
 *
 \par
 * Alternative to CBDATA_INIT_TYPE()
 *
 \param type		Type being initialized
 \param free_func	The freehandler called when the last known reference to an allocated entry goes away.
 */
#define CBDATA_INIT_TYPE_FREECB(type, free_func)	(CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), free_func)))

/**
 \ingroup CBDATA
 *
 * A generic wrapper for passing objects through cbdata.
 * Use this when you need to pass callback data to a blocking
 * operation, but you don't want to/cannot have that pointer be cbdata itself.
 */
class generic_cbdata
{
public:

    generic_cbdata(void * data) : data(data) {}

    template<typename wrapped_type>void unwrap(wrapped_type **output) {
        *output = static_cast<wrapped_type *>(data);
        delete this;
    }

    /**
     * The wrapped data - only public to allow the mild abuse of this facility
     * done by store_swapout - it gives a wrapped StoreEntry to StoreIO as the
     * object to be given to the callbacks. That needs to be fully cleaned up!
     * - RBC 20060820
     \todo CODE: make this a private field.
     */
    void *data; /* the wrapped data */
private:
    CBDATA_CLASS2(generic_cbdata);
};

#endif /* SQUID_CBDATA_H */
