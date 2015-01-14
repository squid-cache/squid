/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_LEAKCHECK_H
#define _SQUID_LEAKCHECK_H

#if LEAK_CHECK_MODE && 0 /* doesn't work at the moment */
#define LOCAL_ARRAY(type,name,size) \
        static type *local_##name=NULL; \
        type *name = local_##name ? local_##name : \
                ( local_##name = (type *)xcalloc(size, sizeof(type)) )
#else
#define LOCAL_ARRAY(type,name,size) static type name[size]
#endif

#endif

