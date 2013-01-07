/*
 * DEBUG: section 79    Disk IO Routines
 */

#include "squid.h"
#include "fs/rock/RockDbCell.h"

Rock::DbCellHeader::DbCellHeader()
{
    memset(this, 0, sizeof(*this));
}
