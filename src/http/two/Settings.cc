/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "http/two/forward.h"
#include "http/two/Frame.h"
#include "http/two/Settings.h"
#include "SquidConfig.h"

Http2::SettingsMap &
Http2::StdDefaultSettings()
{
    /* initialize a SETTINGS parameter list with default values.
     * see RFC 7540 section 6.5.2 and 4.2
     */
    static Http2::SettingsMap StandardDefaultSettings;
    if (StandardDefaultSettings.empty()) {
        StandardDefaultSettings[Http2::SETTINGS_HEADER_TABLE_SIZE] = 4096;
        StandardDefaultSettings[Http2::SETTINGS_ENABLE_PUSH] = 1;
        /* Http2::SETTINGS_MAX_CONCURRENT_STREAMS has no default limit */
        StandardDefaultSettings[Http2::SETTINGS_INITIAL_WINDOW_SIZE] = (2^16)-1;
        StandardDefaultSettings[Http2::SETTINGS_MAX_FRAME_SIZE] = Http2::MaxFramePayloadSz;
        /* Http2::SETTINGS_MAX_HEADER_LIST_SIZE] has no default limit */
    }

    return StandardDefaultSettings;
}

void
Http2::SquidDefaultSettings(Packable &buf)
{
    /* initialize a SETTINGS parameter list with default values
     * that Squid prefers.
     */
    static Http2::SettingsMap SquidDefaults;
    if (SquidDefaults.empty()) {
        SquidDefaults[Http2::SETTINGS_HEADER_TABLE_SIZE] = 4096;
        SquidDefaults[Http2::SETTINGS_ENABLE_PUSH] = 0;
        SquidDefaults[Http2::SETTINGS_INITIAL_WINDOW_SIZE] = (2^16)-1;
        SquidDefaults[Http2::SETTINGS_MAX_FRAME_SIZE] = Http2::MaxFrameExtendedSz;
        SquidDefaults[Http2::SETTINGS_MAX_HEADER_LIST_SIZE] = 64*1024; // 64KB
    }
    // these may change dynamically with reconfigure, so set it new every time.
    SquidDefaults[Http2::SETTINGS_MAX_CONCURRENT_STREAMS] = Config.pipeline_max_prefetch;

    // pack the above for delivery as SETTINGS payload
    for (auto &i : SquidDefaults) {
        SettingParameter param(i.first, i.second);
        buf.append(reinterpret_cast<char*>(param.data), sizeof(param.data));
    }
}
