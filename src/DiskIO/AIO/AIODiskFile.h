
/*
 * $Id: AIODiskFile.h,v 1.2 2006/08/21 00:50:43 robertc Exp $
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

#ifndef SQUID_AIODISKFILE_H
#define SQUID_AIODISKFILE_H

#include "DiskIO/DiskFile.h"
#include "async_io.h"
#include "cbdata.h"

class AIODiskIOStrategy;

class AIODiskFile : public DiskFile
{

public:

    friend class AIODiskIOStrategy;
    void * operator new (size_t);
    void operator delete (void *);
    AIODiskFile (char const *path, AIODiskIOStrategy *);
    ~AIODiskFile();
    virtual void open (int, mode_t, RefCount<IORequestor>);
    virtual void create (int, mode_t, RefCount<IORequestor>);
    virtual void read(ReadRequest *);
    virtual void write(WriteRequest *);
    virtual void close ();
    virtual bool canRead() const;
    virtual bool canWrite() const;

    /* During migration only */
    virtual int getFD() const;

    virtual bool error() const;

    /* Inform callers if there is IO in progress */
    virtual bool ioInProgress() const;

private:
    CBDATA_CLASS(AIODiskFile);
    void error(bool const &);
    int fd;
    String path;
    AIODiskIOStrategy *strategy;
    RefCount<IORequestor> ioRequestor;
    bool closed;
    bool error_;
};

#endif /* SQUID_AIODISKFILE_H */
