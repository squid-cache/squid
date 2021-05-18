/*
 * Copyright (C) 1996-2021 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 86    ESI processing */

#include "squid.h"

/* MS Visual Studio Projects are monolithic, so we need the following
 * #if to exclude the ESI code from compile process when not needed.
 */
#if (USE_SQUID_ESI == 1)

#include "esi/Assign.h"
#include "esi/Context.h"
#include "esi/Sequence.h"
#include "HttpReply.h"

ESIAssign::~ESIAssign()
{
    if (value)
        delete value;
}

ESIAssign::ESIAssign (ESIAssign const &old) : parent (NULL), varState (NULL), name (old.name), value (old.value ? new ESIVariableExpression (*old.value): NULL), variable (NULL), unevaluatedVariable(old.unevaluatedVariable)
{}

ESIAssign::ESIAssign (esiTreeParentPtr aParent, int attrcount, char const **attr, ESIContext *aContext) : parent (aParent), varState (NULL), name(), value (NULL), variable (NULL), unevaluatedVariable()
{
    /* TODO: grab content IFF no value was specified */
    assert (aContext);

    for (int i = 0; i < attrcount && attr[i]; i += 2) {
        if (!strcmp(attr[i],"name")) {
            /* the variables name is ...  */
            debugs(86, 5, "ESIAssign::ESIAssign: Variable name '" << attr[i+1] << "'");
            /* If there are duplicate name attributes, we simply use the
             * last one
             */
            name = attr[i+1];
        } else if (!strcmp(attr[i],"value")) {
            /* short form assignment:  */
            debugs(86, 5, "ESIAssign::ESIAssign: Unevaluated variable '" << attr[i+1] << "'");
            /* Again, if there are duplicate attributes, we use the last */
            unevaluatedVariable = attr[i+1];
        } else {
            /* ignore mistyped attributes. TODO:? error on these for user feedback - config parameter needed
             */
        }
    }

    varState = cbdataReference(aContext->varState);
}

void
ESIAssign::evaluateVariable()
{
    if (variable.getRaw())
        variable->process (false);

    variable = NULL;

    if (unevaluatedVariable.size()) {
        varState->feedData(unevaluatedVariable.rawBuf(), unevaluatedVariable.size());
        char const *result = varState->extractChar ();

        /* Consider activating this, when we want to evaluate variables to a
         * value
         */
        // setTestResult(ESIExpression::Evaluate (expression));

        value = new ESIVariableExpression (result);

        safe_free (result);
    }
}

void
ESIAssign::provideData (ESISegment::Pointer data, ESIElement * source)
{
    assert (source == variable.getRaw());
    char *result = data->listToChar();
    unevaluatedVariable = result;
    safe_free (result);
}

esiProcessResult_t
ESIAssign::process (int dovars)
{
    assert (varState);

    if (!value)
        evaluateVariable();

    if (!value)
        return ESI_PROCESS_COMPLETE;

    varState->addVariable (name.rawBuf(), name.size(), value);

    value = NULL;

    debugs(86, 5, "ESIAssign: Processed " << this);

    return ESI_PROCESS_COMPLETE;
}

void
ESIAssign::render(ESISegment::Pointer)
{}

ESIAssign::Pointer
ESIAssign::makeCacheable() const
{
    ESIAssign *result = new ESIAssign (*this);

    if (variable.getRaw())
        result->variable = variable->makeCacheable();

    return result;
}

ESIAssign::Pointer
ESIAssign::makeUsable(esiTreeParentPtr aParent, ESIVarState &aVarState) const
{
    ESIAssign *result = new ESIAssign (*this);
    result->parent = aParent;
    result->varState = cbdataReference(&aVarState);

    if (variable.getRaw())
        result->variable = variable->makeUsable(result, aVarState);

    return result;
}

void
ESIAssign::finish()
{
    if (varState)
        cbdataReferenceDone (varState);

    if (parent.getRaw())
        parent = NULL;
}

bool
ESIAssign::addElement(ESIElement::Pointer anElement)
{
    /* we have a value, drop the element on the floor */

    if (unevaluatedVariable.size())
        return true;

    if (!variable.getRaw())
        variable = new esiSequence (this, false);

    return variable->addElement (anElement);
}

ESIVariableExpression::~ESIVariableExpression()
{}

ESIVariableExpression::ESIVariableExpression (String const &aString) : expression (aString)
{}

void
ESIVariableExpression::eval (ESIVarState &state, char const *subref, char const *defaultOnEmpty) const
{
    /* XXX: Implement evaluation of the expression */
    ESISegment::ListAppend (state.getOutput(), expression.rawBuf(), expression.size());
}

#endif /* USE_SQUID_ESI == 1 */

