
/*
 * $Id: cbdata.h,v 1.1 2006/08/21 00:50:41 robertc Exp $
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

/*
 * cbdata types. similar to the MEM_* types above, but managed
 * in cbdata.c. A big difference is that these types are dynamically
 * allocated. This list is only a list of predefined types. Other types
 * are added runtime
 */
typedef enum {
    CBDATA_UNKNOWN = 0,
} cbdata_type;

extern void cbdataRegisterWithCacheManager(CacheManager & manager);
#if CBDATA_DEBUG
extern void *cbdataInternalAllocDbg(cbdata_type type, const char *, int);
extern void *cbdataInternalFreeDbg(void *p, const char *, int);
extern void cbdataInternalLockDbg(const void *p, const char *, int);
extern void cbdataInternalUnlockDbg(const void *p, const char *, int);
extern int cbdataInternalReferenceDoneValidDbg(void **p, void **tp, const char *, int);
#else
extern void *cbdataInternalAlloc(cbdata_type type);
extern void *cbdataInternalFree(void *p);
extern void cbdataInternalLock(const void *p);
extern void cbdataInternalUnlock(const void *p);
extern int cbdataInternalReferenceDoneValid(void **p, void **tp);
#endif
extern int cbdataReferenceValid(const void *p);
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
	private:
#else
#define cbdataAlloc(type) ((type *)cbdataInternalAlloc(CBDATA_##type))
#define cbdataFree(var)		do {if (var) {cbdataInternalFree(var); var = NULL;}} while(0)
#define cbdataReferenceValidDone(var, ptr) cbdataInternalReferenceDoneValid((void **)&(var), (ptr))
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
	private:
#endif
#define cbdataReference(var)	(cbdataInternalLock(var), var)
#define cbdataReferenceDone(var) do {if (var) {cbdataInternalUnlock(var); var = NULL;}} while(0)
#define CBDATA_CLASS(type)	static cbdata_type CBDATA_##type
#define CBDATA_CLASS_INIT(type) cbdata_type type::CBDATA_##type = CBDATA_UNKNOWN
#define CBDATA_TYPE(type)	static cbdata_type CBDATA_##type = CBDATA_UNKNOWN
#define CBDATA_GLOBAL_TYPE(type)	cbdata_type CBDATA_##type
#define CBDATA_INIT_TYPE(type)	(CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), NULL)))
#define CBDATA_INIT_TYPE_FREECB(type, free_func)	(CBDATA_##type ?  CBDATA_UNKNOWN : (CBDATA_##type = cbdataInternalAddType(CBDATA_##type, #type, sizeof(type), free_func)))

/*
 * use this when you need to pass callback data to a blocking
 * operation, but you don't want to/cannot have that pointer be cbdata itself.
 */

class generic_cbdata
{
  public:
    generic_cbdata(void * data) : data(data) {}
    template<typename wrapped_type>void unwrap(wrapped_type **output) 
      {
	*output = static_cast<wrapped_type *>(data);
	delete this;
      }
    /* the wrapped data - only public to allow the mild abuse of this facility
     * done by store_swapout - it gives a wrapped StoreEntry to StoreIO as the
     * object to be given to the callbacks. That needs to be fully cleaned up!
     * - RBC 20060820
     */
    void *data; /* the wrapped data */
  private:
    CBDATA_CLASS2(generic_cbdata);
};



#endif /* SQUID_CBDATA_H */
