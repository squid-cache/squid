/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef STUB

/** \group STUB
 *
 *  A set of useful macros to create stub_* files.
 *
 * Intended for use building unit tests, if a stubbed function is called
 * by any code it is linked to it will abort with a message indicating
 * which API file is missing from the linked dependencies.
 *
 * Usage:
 *    at the top of your intended stub file define STUB_API to be the
 *    name of the .cc file or library you are providing a stub of
 *    then include this STUB.h header.
 *
 *   #define STUB_API "foo/libexample.la"
 *   #include "tests/STUB.h"
 */
#include <iostream>

// Internal Special: the STUB framework requires this function
#define stub_fatal(m) { std::cerr<<"FATAL: "<<(m)<<" for use of "<<__FUNCTION__<<"\n"; exit(1); }

/// macro to stub a void function.
#define STUB { stub_fatal(STUB_API " required"); }

/// macro to stub a void function without a fatal message
/// Intended for registration pattern APIs where the function result does not matter to the test
#define STUB_NOP { std::cerr<<"SKIP: "<<STUB_API<<" "<<__FUNCTION__<<" (not implemented).\n"; }

/// macro to stub a function with return value.
/// Aborts unit tests requiring its definition with a message about the missing linkage
#define STUB_RETVAL(x) { stub_fatal(STUB_API " required"); return x; }

/// macro to stub a void function without a fatal message and with a return value
/// Intended for registration pattern APIs where the function result does not matter to the test
#define STUB_RETVAL_NOP(x) { std::cerr<<"SKIP: "<<STUB_API<<" "<<__FUNCTION__<<" (not implemented).\n"; return x; }

/** macro to stub a function which returns a reference to dynamic
 *  Aborts unit tests requiring its definition with a message about the missing linkage
 *  \param x underlying or "referred to" type
 */
#define STUB_RETREF(x) { stub_fatal(STUB_API " required"); return *(x *)nullptr; }

/** Same as STUB_RETREF(). TODO: Remove */
#define STUB_RETSTATREF(x) STUB_RETREF(x)

#endif /* STUB */

