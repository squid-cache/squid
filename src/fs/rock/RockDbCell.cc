/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 79    Disk IO Routines */

#include "squid.h"
#include "fs/rock/RockDbCell.h"

Rock::DbCellHeader::DbCellHeader()
{
    memset(this, 0, sizeof(*this));
}

