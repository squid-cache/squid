/*
 * DEBUG: section 86    ESI processing
 * AUTHOR: Robert Collins
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

#ifndef SQUID_ESIASSIGN_H
#define SQUID_ESIASSIGN_H

#include "esi/Element.h"
#include "esi/VarState.h"
#include "SquidString.h"

/* ESIVariableExpression */
/* This is a variable that is itself and expression */

class ESIVariableExpression : public ESIVarState::Variable
{

public:
    ~ESIVariableExpression();
    ESIVariableExpression (String const &value);
    virtual void eval (ESIVarState &state, char const *, char const *) const;

private:
    String expression;
};

/* ESIAssign */

class ESIContext;

class ESIAssign : public ESIElement
{

public:
    MEMPROXY_CLASS(ESIAssign);
    ESIAssign (esiTreeParentPtr, int, const char **, ESIContext *);
    ESIAssign (ESIAssign const &);
    ESIAssign &operator=(ESIAssign const &);
    ~ESIAssign();
    esiProcessResult_t process (int dovars);
    void render(ESISegment::Pointer);
    bool addElement(ESIElement::Pointer);
    void provideData (ESISegment::Pointer data, ESIElement * source);
    Pointer makeCacheable() const;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const;
    void finish();

private:
    void evaluateVariable();
    esiTreeParentPtr parent;
    ESIVarState *varState;
    String name;
    ESIVariableExpression * value;
    ESIElement::Pointer variable;
    String unevaluatedVariable;
};

MEMPROXY_CLASS_INLINE(ESIAssign);

#endif /* SQUID_ESIASSIGN_H */
