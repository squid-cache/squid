
/*
 * $Id: DiskFile.h,v 1.1 2004/12/20 16:30:38 robertc Exp $
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
 * Copyright (c) 2003 Robert Collins <robertc@squid-cache.org>
 */

#ifndef SQUID_DISKFILE_H
#define SQUID_DISKFILE_H

#include "squid.h"

#include "RefCount.h"

class IORequestor;

class ReadRequest;

class WriteRequest;

class DiskFile : public RefCountable
{

public:
    typedef RefCount<DiskFile> Pointer;
    virtual void open (int, mode_t, RefCount<IORequestor>) = 0;
    virtual void create (int, mode_t, RefCount<IORequestor>) = 0;
    virtual void read(ReadRequest *) = 0;
    virtual void write(WriteRequest *) = 0;
    virtual void close () = 0;
    virtual bool canRead() const = 0;
    virtual bool canWrite() const {return true;}

    /* During miogration only */
    virtual int getFD() const {return -1;}

    virtual bool error() const = 0;

    /* Inform callers if there is IO in progress */
    virtual bool ioInProgress() const = 0;
};

#endif /* SQUID_DISKFILE_H */
