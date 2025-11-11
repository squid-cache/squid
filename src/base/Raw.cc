/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "base/IoManip.h"
#include "base/Raw.h"
#include "debug/Stream.h"

#include <iostream>

std::ostream &
Raw::print(std::ostream &os) const
{
    if (label_)
        os << ' ' << label_ << '[' << size_ << ']';

    if (!size_)
        return os;

    // finalize debugging level if no level was set explicitly via minLevel()
    const auto printLimit = std::min(size_, printableSize_);
    const int finalLevel = (level >= 0) ? level :
                           (printLimit > 40 ? DBG_DATA : Debug::SectionLevel());
    if (finalLevel <= Debug::SectionLevel()) {
        if (label_)
            os << '=';
        else if (useGap_)
            os << ' ';
        if (data_) {
            const auto data = static_cast<const char *>(data_);
            if (useHex_)
                PrintHex(os, data, printLimit);
            else
                os.write(data, printLimit);
            if (printLimit < size_)
                os << "[..." << (size_ - printLimit) << " bytes...]";
        } else {
            os << "[null]";
        }
    }

    return os;
}

