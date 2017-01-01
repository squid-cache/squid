/*
 * Copyright (C) 1996-2017 The Squid Software Foundation and contributors
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

#include "client_side_request.h"
#include "esi/Context.h"
#include "Store.h"

void
ESIContext::updateCachedAST()
{
    assert (http);
    assert (http->storeEntry());

    if (hasCachedAST()) {
        debugs(86, 5, "ESIContext::updateCachedAST: not updating AST cache for entry " <<
               http->storeEntry() << " from ESI Context " << this <<
               " as there is already a cached AST.");

        return;
    }

    ESIElement::Pointer treeToCache = tree->makeCacheable();
    debugs(86, 5, "ESIContext::updateCachedAST: Updating AST cache for entry " <<
           http->storeEntry() << " with current value " <<
           http->storeEntry()->cachedESITree.getRaw() << " to new value " <<
           treeToCache.getRaw());

    if (http->storeEntry()->cachedESITree.getRaw())
        http->storeEntry()->cachedESITree->finish();

    http->storeEntry()->cachedESITree = treeToCache;

    treeToCache = NULL;
}

bool
ESIContext::hasCachedAST() const
{
    assert (http);
    assert (http->storeEntry());

    if (http->storeEntry()->cachedESITree.getRaw()) {
        debugs(86, 5, "ESIContext::hasCachedAST: " << this <<
               " - Cached AST present in store entry " << http->storeEntry() << ".");
        return true;
    } else {
        debugs(86, 5, "ESIContext::hasCachedAST: " << this <<
               " - Cached AST not present in store entry " << http->storeEntry() << ".");
        return false;
    }
}

void
ESIContext::getCachedAST()
{
    if (cachedASTInUse)
        return;

    assert (hasCachedAST());

    assert (varState);

    parserState.popAll();

    tree = http->storeEntry()->cachedESITree->makeUsable (this, *varState);

    cachedASTInUse = true;
}

void
ESIContext::setErrorMessage(char const *anError)
{
    if (!errormessage)
        errormessage = xstrdup(anError);
}

#endif /* USE_SQUID_ESI == 1 */

