/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 16    Cache Manager API */

#ifndef SQUID_SRC_MGR_ACTIONWRITER_H
#define SQUID_SRC_MGR_ACTIONWRITER_H

#include "comm/forward.h"
#include "mgr/StoreToCommWriter.h"

namespace Mgr
{

/// Creates Store entry, fills it using action's fillEntry(), and
/// Comm-writes it using parent StoreToCommWriter.
class ActionWriter: public StoreToCommWriter
{
    CBDATA_CHILD(ActionWriter);

public:
    ActionWriter(const Action::Pointer &anAction, const Comm::ConnectionPointer &conn);

protected:
    /* AsyncJob API */
    void start() override;

private:
    Action::Pointer action; ///< action that fills the entry
};

} // namespace Mgr

#endif /* SQUID_SRC_MGR_ACTIONWRITER_H */

