/*
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
 *  Author: kinkie
 *
 */

#ifndef HTTPBODY_H_
#define HTTPBODY_H_

#include "MemBuf.h"
class Packer;

/** Representation of a short predetermined message
 *
 * This class is useful to represent short HTTP messages, whose
 * contents are known in advance, e.g. error messages
 */
class HttpBody
{
public:
    HttpBody();
    ~HttpBody();
    /** absorb the MemBuf, discarding anything currently stored
     *
     * After this call the lifetime of the passed MemBuf is managed
     * by the HttpBody.
     */
    void setMb(MemBuf *);
    /** output the HttpBody contents into the supplied packer
     *
     * \note content is not cleared by the output operation
     */
    void packInto(Packer *) const;

    /// clear the HttpBody content
    void clear();

    /// \return true if there is any content in the HttpBody
    bool hasContent() const { return (mb->contentSize()>0); }

    /// \return size of the HttpBody's message content
    mb_size_t contentSize() const { return mb->contentSize(); }

    /// \return pointer to the storage of the HttpBody
    char *content() const { return mb->content(); }
private:
    HttpBody& operator=(const HttpBody&); //not implemented
    HttpBody(const HttpBody&); // not implemented
    MemBuf *mb;
};

#endif /* HTTPBODY_H_ */
