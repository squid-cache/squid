/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

// Author:  Jens-S. V?ckler <voeckler@rvs.uni-hannover.de>
//
// File:    squid-tlv.cc
//          Tue Jun 15 1999
//
// (c) 1999 Lehrgebiet Rechnernetze und Verteilte Systeme
//          Universit?t Hannover, Germany
//
// Permission to use, copy, modify, distribute, and sell this software
// and its documentation for any purpose is hereby granted without fee,
// provided that (i) the above copyright notices and this permission
// notice appear in all copies of the software and related documentation,
// and (ii) the names of the Lehrgebiet Rechnernetze und Verteilte
// Systeme and the University of Hannover may not be used in any
// advertising or publicity relating to the software without the
// specific, prior written permission of Lehrgebiet Rechnernetze und
// Verteilte Systeme and the University of Hannover.
//
// THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
// EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
// WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
//
// IN NO EVENT SHALL THE LEHRGEBIET RECHNERNETZE UND VERTEILTE SYSTEME OR
// THE UNIVERSITY OF HANNOVER BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
// INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT
// ADVISED OF THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY,
// ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
// SOFTWARE.
//
// Revision 1.1  1999/06/15 21:10:16  voeckler
// Initial revision
//

#include "squid.h"
#include "squid-tlv.hh"

SquidTLV::SquidTLV( SquidMetaType _type, size_t _size, void* _data )
    :next(nullptr),size(_size)
{
    type = _type;
    data = (char*) _data;
}

SquidMetaList::SquidMetaList()
{
    head = tail = nullptr;
}

SquidMetaList::~SquidMetaList()
{
    for ( SquidTLV* temp = head; temp; temp = head ) {
        head = temp->next;
        delete temp;
    }
}

void
SquidMetaList::append( SquidMetaType type, size_t size, void* data )
{
    SquidTLV* temp = new SquidTLV( type, size, data );
    if ( head == nullptr ) head = tail = temp;
    else {
        tail->next = temp;
        tail = temp;
    }
}

const SquidTLV*
SquidMetaList::search( SquidMetaType type ) const
{
    const SquidTLV* temp = head;
    while ( temp && temp->type != type ) temp = temp->next;
    return temp;
}

