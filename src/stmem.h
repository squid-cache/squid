
/*
 * $Id: stmem.h,v 1.1 2003/01/23 00:37:26 robertc Exp $
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

#ifndef SQUID_STMEM_H
#define SQUID_STMEM_H

class mem_node;
class StoreIOBuffer;
class mem_hdr {
public:
    void freeContent();
    int lowestOffset () const;
    off_t endOffset () const;
    int freeDataUpto (int);
    ssize_t copy (off_t, char *, size_t) const;
    bool hasContigousContentRange(size_t start, size_t end) const;
    /* success or fail */
    bool write (StoreIOBuffer const &);

    /* Only for use of MemObject */
    void internalAppend(const char *data, int len);
    mem_node *head;
    mem_node *tail;
private:
    void unlinkHead();
    void makeAppendSpace();
    int appendToNode(mem_node *aNode, const char *data, int maxLength);
    void appendNode (mem_node *aNode);
    mem_node *getBlockContainingLocation (size_t location) const;
    size_t copyAvailable(mem_node *aNode, size_t location, size_t amount, char *target) const;
    bool unionNotEmpty (StoreIOBuffer const &);
    mem_node *getHighestBlockBeforeLocation (size_t location) const;
    mem_node *nodeToRecieve(off_t offset);
    size_t writeAvailable(mem_node *aNode, size_t location, size_t amount, char const *source);
    off_t inmem_hi;
};

#endif /* SQUID_STMEM_H */
