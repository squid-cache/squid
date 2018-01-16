/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_BASE_HARDFUN_H
#define _SQUID_SRC_BASE_HARDFUN_H

/**
 * A functor that calls a hard-coded unary function.
 */
template <class ReturnType, class ArgType, ReturnType (*fun)(ArgType)>
struct HardFun {
    ReturnType operator()(ArgType arg) { return fun(arg); }
};

#endif /* _SQUID_SRC_BASE_HARDFUN_H */

