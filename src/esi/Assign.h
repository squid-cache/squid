/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

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

