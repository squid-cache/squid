/*
 * $Id: dlmalloc.c,v 1.3 2001/01/07 09:55:22 hno Exp $
 */

/* ---------- To make a malloc.h, start cutting here ------------ */

/* 
 * A version of malloc/free/realloc written by Doug Lea and released to the 
 * public domain.  Send questions/comments/complaints/performance data
 * to dl@cs.oswego.edu
 * 
 * * VERSION 2.6.4  Thu Nov 28 07:54:55 1996  Doug Lea  (dl at gee)
 * 
 * Note: There may be an updated version of this malloc obtainable at
 * ftp://g.oswego.edu/pub/misc/malloc.c
 * Check before installing!
 * 
 * * Why use this malloc?
 * 
 * This is not the fastest, most space-conserving, most portable, or
 * most tunable malloc ever written. However it is among the fastest
 * while also being among the most space-conserving, portable and tunable.
 * Consistent balance across these factors results in a good general-purpose 
 * allocator. For a high-level description, see 
 * http://g.oswego.edu/dl/html/malloc.html
 * 
 * * Synopsis of public routines
 * 
 * (Much fuller descriptions are contained in the program documentation below.)
 * 
 * malloc(size_t n);
 * Return a pointer to a newly allocated chunk of at least n bytes, or null
 * if no space is available.
 * free(Void_t* p);
 * Release the chunk of memory pointed to by p, or no effect if p is null.
 * realloc(Void_t* p, size_t n);
 * Return a pointer to a chunk of size n that contains the same data
 * as does chunk p up to the minimum of (n, p's size) bytes, or null
 * if no space is available. The returned pointer may or may not be
 * the same as p. If p is null, equivalent to malloc.  Unless the
 * #define REALLOC_ZERO_BYTES_FREES below is set, realloc with a
 * size argument of zero (re)allocates a minimum-sized chunk.
 * memalign(size_t alignment, size_t n);
 * Return a pointer to a newly allocated chunk of n bytes, aligned
 * in accord with the alignment argument, which must be a power of
 * two.
 * valloc(size_t n);
 * Equivalent to memalign(pagesize, n), where pagesize is the page
 * size of the system (or as near to this as can be figured out from
 * all the includes/defines below.)
 * pvalloc(size_t n);
 * Equivalent to valloc(minimum-page-that-holds(n)), that is,
 * round up n to nearest pagesize.
 * calloc(size_t unit, size_t quantity);
 * Returns a pointer to quantity * unit bytes, with all locations
 * set to zero.
 * cfree(Void_t* p);
 * Equivalent to free(p).
 * malloc_trim(size_t pad);
 * Release all but pad bytes of freed top-most memory back 
 * to the system. Return 1 if successful, else 0.
 * malloc_usable_size(Void_t* p);
 * Report the number usable allocated bytes associated with allocated
 * chunk p. This may or may not report more bytes than were requested,
 * due to alignment and minimum size constraints.
 * malloc_stats();
 * Prints brief summary statistics on stderr.
 * mallinfo()
 * Returns (by copy) a struct containing various summary statistics.
 * mallopt(int parameter_number, int parameter_value)
 * Changes one of the tunable parameters described below. Returns
 * 1 if successful in changing the parameter, else 0.
 * 
 * * Vital statistics:
 * 
 * Alignment:                            8-byte
 * 8 byte alignment is currently hardwired into the design.  This
 * seems to suffice for all current machines and C compilers.
 * 
 * Assumed pointer representation:       4 or 8 bytes
 * Code for 8-byte pointers is untested by me but has worked
 * reliably by Wolfram Gloger, who contributed most of the
 * changes supporting this.
 * 
 * Assumed size_t  representation:       4 or 8 bytes
 * Note that size_t is allowed to be 4 bytes even if pointers are 8.        
 * 
 * Minimum overhead per allocated chunk: 4 or 8 bytes
 * Each malloced chunk has a hidden overhead of 4 bytes holding size
 * and status information.  
 * 
 * Minimum allocated size: 4-byte ptrs:  16 bytes    (including 4 overhead)
 * 8-byte ptrs:  24/32 bytes (including, 4/8 overhead)
 * 
 * When a chunk is freed, 12 (for 4byte ptrs) or 20 (for 8 byte
 * ptrs but 4 byte size) or 24 (for 8/8) additional bytes are 
 * needed; 4 (8) for a trailing size field
 * and 8 (16) bytes for free list pointers. Thus, the minimum
 * allocatable size is 16/24/32 bytes.
 * 
 * Even a request for zero bytes (i.e., malloc(0)) returns a
 * pointer to something of the minimum allocatable size.
 * 
 * Maximum allocated size: 4-byte size_t: 2^31 -  8 bytes
 * 8-byte size_t: 2^63 - 16 bytes
 * 
 * It is assumed that (possibly signed) size_t bit values suffice to
 * represent chunk sizes. `Possibly signed' is due to the fact
 * that `size_t' may be defined on a system as either a signed or
 * an unsigned type. To be conservative, values that would appear
 * as negative numbers are avoided.  
 * Requests for sizes with a negative sign bit will return a
 * minimum-sized chunk.
 * 
 * Maximum overhead wastage per allocated chunk: normally 15 bytes
 * 
 * Alignnment demands, plus the minimum allocatable size restriction
 * make the normal worst-case wastage 15 bytes (i.e., up to 15
 * more bytes will be allocated than were requested in malloc), with 
 * two exceptions:
 * 1. Because requests for zero bytes allocate non-zero space,
 * the worst case wastage for a request of zero bytes is 24 bytes.
 * 2. For requests >= mmap_threshold that are serviced via
 * mmap(), the worst case wastage is 8 bytes plus the remainder
 * from a system page (the minimal mmap unit); typically 4096 bytes.
 * 
 * * Limitations
 * 
 * Here are some features that are NOT currently supported
 * 
 * * No user-definable hooks for callbacks and the like.
 * * No automated mechanism for fully checking that all accesses
 * to malloced memory stay within their bounds.
 * * No support for compaction.
 * 
 * * Synopsis of compile-time options:
 * 
 * People have reported using previous versions of this malloc on all
 * versions of Unix, sometimes by tweaking some of the defines
 * below. It has been tested most extensively on Solaris and
 * Linux. It is also reported to work on WIN32 platforms.
 * People have also reported adapting this malloc for use in
 * stand-alone embedded systems.
 * 
 * The implementation is in straight, hand-tuned ANSI C.  Among other
 * consequences, it uses a lot of macros.  Because of this, to be at
 * all usable, this code should be compiled using an optimizing compiler
 * (for example gcc -O2) that can simplify expressions and control
 * paths.
 * 
 * __STD_C                  (default: derived from C compiler defines)
 * Nonzero if using ANSI-standard C compiler, a C++ compiler, or
 * a C compiler sufficiently close to ANSI to get away with it.
 * DEBUG                    (default: NOT defined)
 * Define to enable debugging. Adds fairly extensive assertion-based 
 * checking to help track down memory errors, but noticeably slows down
 * execution.
 * REALLOC_ZERO_BYTES_FREES (default: NOT defined) 
 * Define this if you think that realloc(p, 0) should be equivalent
 * to free(p). Otherwise, since malloc returns a unique pointer for
 * malloc(0), so does realloc(p, 0).
 * HAVE_MEMCPY               (default: defined)
 * Define if you are not otherwise using ANSI STD C, but still 
 * have memcpy and memset in your C library and want to use them.
 * Otherwise, simple internal versions are supplied.
 * USE_MEMCPY               (default: 1 if HAVE_MEMCPY is defined, 0 otherwise)
 * Define as 1 if you want the C library versions of memset and
 * memcpy called in realloc and calloc (otherwise macro versions are used). 
 * At least on some platforms, the simple macro versions usually
 * outperform libc versions.
 * HAVE_MMAP                 (default: defined as 1)
 * Define to non-zero to optionally make malloc() use mmap() to
 * allocate very large blocks.  
 * HAVE_MREMAP                 (default: defined as 0 unless Linux libc set)
 * Define to non-zero to optionally make realloc() use mremap() to
 * reallocate very large blocks.  
 * malloc_getpagesize        (default: derived from system #includes)
 * Either a constant or routine call returning the system page size.
 * HAVE_USR_INCLUDE_MALLOC_H (default: NOT defined) 
 * Optionally define if you are on a system with a /usr/include/malloc.h
 * that declares struct mallinfo. It is not at all necessary to
 * define this even if you do, but will ensure consistency.
 * INTERNAL_SIZE_T           (default: size_t)
 * Define to a 32-bit type (probably `unsigned int') if you are on a 
 * 64-bit machine, yet do not want or need to allow malloc requests of 
 * greater than 2^31 to be handled. This saves space, especially for
 * very small chunks.
 * INTERNAL_LINUX_C_LIB      (default: NOT defined)
 * Defined only when compiled as part of Linux libc.
 * Also note that there is some odd internal name-mangling via defines
 * (for example, internally, `malloc' is named `mALLOc') needed
 * when compiling in this case. These look funny but don't otherwise
 * affect anything.
 * WIN32                     (default: undefined)
 * Define this on MS win (95, nt) platforms to compile in sbrk emulation.
 * LACKS_UNISTD_H            (default: undefined)
 * Define this if your system does not have a <unistd.h>.
 * MORECORE                  (default: sbrk)
 * The name of the routine to call to obtain more memory from the system.
 * MORECORE_FAILURE          (default: -1)
 * The value returned upon failure of MORECORE.
 * MORECORE_CLEARS           (default 1)
 * True (1) if the routine mapped to MORECORE zeroes out memory (which
 * holds for sbrk).
 * DEFAULT_TRIM_THRESHOLD
 * DEFAULT_TOP_PAD       
 * DEFAULT_MMAP_THRESHOLD
 * DEFAULT_MMAP_MAX      
 * Default values of tunable parameters (described in detail below)
 * controlling interaction with host system routines (sbrk, mmap, etc).
 * These values may also be changed dynamically via mallopt(). The
 * preset defaults are those that give best performance for typical
 * programs/systems.
 * 
 * 
 */




/* Preliminaries */

#ifndef __STD_C
#ifdef __STDC__
#define __STD_C     1
#else
#if __cplusplus
#define __STD_C     1
#else
#define __STD_C     0
#endif
/*__cplusplus*/
