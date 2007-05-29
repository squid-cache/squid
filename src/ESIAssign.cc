
/*
 * $Id: ESIAssign.cc,v 1.6 2007/05/29 13:31:37 amosjeffries Exp $
 *
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
 ;  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "ESIAssign.h"
#include "ESIContext.h"
#include "ESISequence.h"

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
        varState->feedData(unevaluatedVariable.buf(), unevaluatedVariable.size());
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

    varState->addVariable (name.buf(), name.size(), value);

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
    ESISegment::ListAppend (state.getOutput(), expression.buf(), expression.size());
}
