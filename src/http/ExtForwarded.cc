/*
 * Copyright (C) 1996-2025 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "ConfigOption.h"
#include "ConfigParser.h"
#include "http/ExtForwarded.h"
#include "sbuf/SBuf.h"

#include <ostream>

Http::ExtForwarded::ExtForwarded(ConfigParser &parser)
{
    auto t = parser.token("Forwarded action");

    // legacy X-Forwarded-For modes
    if (t.cmp("on") == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: action 'on' is deprecated. Please remove this line. Use request_header_add instead.");
        mode = Mode::xffOn;
    } else if (t.cmp("off") == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: action 'off' is deprecated. Consider using action 'delete', or removing entirely.");
        mode = Mode::xffOff;
    } else if (t.cmp("truncate") == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: action 'truncate' is deprecated. Consider using action 'delete' instead.");
        mode = Mode::xffTruncate;
    }

    // TODO: else options specific to Forwarded

    // modes shared by X-Forwarded-For and Forwarded
    if (t.cmp("delete") == 0) {
        mode = Mode::fwdDelete;
    } else if (t.cmp("transparent") == 0) {
        debugs(3, DBG_PARSE_NOTE(1), "WARNING: UPGRADE: default action 'transparent' does not need to be configured.");
        mode = Mode::fwdTransparent;
    }
}

void
Http::ExtForwarded::dump(std::ostream &os) const
{
    switch (mode)
    {
    case Mode::fwdDelete:
        os << " delete";
        break;
    case Mode::fwdTransparent: // TODO: default should not be printed
        os << " transparent";
        break;

    // deprecated modes.
    // XXX: Configuration::Component API cannot print the correct squid.conf text for these.
    // XXX: should be printed with the deprecated 'forwarded_for ' directive name
    case Mode::xffOn:
        os << " on";
        break;
    case Mode::xffOff:
        os << " off";
        break;
    case Mode::xffTruncate:
        os << " truncate";
        break;
    }
}
