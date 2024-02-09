/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#ifndef SQUID_SRC_ESI_ASSIGN_H
#define SQUID_SRC_ESI_ASSIGN_H

#include "esi/Element.h"
#include "esi/VarState.h"
#include "SquidString.h"

/** This is a variable that is itself an expression */
class ESIVariableExpression : public ESIVarState::Variable
{
public:
    ~ESIVariableExpression() override;
    ESIVariableExpression (String const &value);
    void eval (ESIVarState &state, char const *, char const *) const override;

private:
    String expression;
};

class ESIContext;

class ESIAssign : public ESIElement
{
    MEMPROXY_CLASS(ESIAssign);

public:
    ESIAssign (esiTreeParentPtr, int, const char **, ESIContext *);
    ESIAssign (ESIAssign const &);
    ESIAssign &operator=(ESIAssign const &);
    ~ESIAssign() override;
    esiProcessResult_t process (int dovars) override;
    void render(ESISegment::Pointer) override;
    bool addElement(ESIElement::Pointer) override;
    void provideData (ESISegment::Pointer data, ESIElement * source) override;
    Pointer makeCacheable() const override;
    Pointer makeUsable(esiTreeParentPtr, ESIVarState &) const override;
    void finish() override;

private:
    void evaluateVariable();
    esiTreeParentPtr parent;
    ESIVarState *varState;
    String name;
    ESIVariableExpression * value;
    ESIElement::Pointer variable;
    String unevaluatedVariable;
};

#endif /* SQUID_SRC_ESI_ASSIGN_H */

