
/*
 * $Id: StoreIOState.h,v 1.6 2003/08/04 22:14:41 robertc Exp $
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
 */

#ifndef SQUID_STOREIOSTATE_H
#define SQUID_STOREIOSTATE_H

#include "RefCount.h"

class storeIOState : public RefCountable
{

public:

    /* storeIOState does not get mempooled - it's children do */
    void *operator new (size_t amount);
    void operator delete (void *address);
    virtual ~storeIOState();

    storeIOState();

    off_t offset() const;

    virtual void read_(char *buf, size_t size, off_t offset, STRCB * callback, void *callback_data) = 0;
    virtual void write(char const *buf, size_t size, off_t offset, FREE * free_func) = 0;
    virtual void close() = 0;

    sdirno swap_dirn;
    sfileno swap_filen;
    StoreEntry *e;		/* Need this so the FS layers can play god */
    mode_t mode;
    off_t offset_;		/* current on-disk offset pointer */
    STFNCB *file_callback;	/* called on delayed sfileno assignments */
    STIOCB *callback;
    void *callback_data;

    struct
    {
        STRCB *callback;
        void *callback_data;
    }

    read;

    struct
    {

unsigned int closing:
        1;	/* debugging aid */
    }

    flags;
};

class StoreIOState
{

public:
    typedef RefCount<storeIOState> Pointer;
};

#endif /* SQUID_STOREIOSTATE_H */
