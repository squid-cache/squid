/*
 * Copyright (C) 1996-2018 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_TWO_SETTINGS_H
#define _SQUID_SRC_HTTP_TWO_SETTINGS_H

#include "base/Packable.h"

#include <map>

namespace Http
{
namespace Two
{

/// HTTP/2 SETTINGS frame parameters
enum SettingsParameterType {
    /* RFC 7540 section 6.5.2 */
    NONE                            = 0x00,
    SETTINGS_HEADER_TABLE_SIZE      = 0x01,
    SETTINGS_ENABLE_PUSH            = 0x02,
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    SETTINGS_INITIAL_WINDOW_SIZE    = 0x04,
    SETTINGS_MAX_FRAME_SIZE         = 0x05,
    SETTINGS_MAX_HEADER_LIST_SIZE   = 0x06

    /* types 0x07-0xff reserved */
};

/// HTTP/2 SETTINGS frame parameter kv-pair
/// RFC 7540 section 6.5.1
struct SettingParameter
{
    SettingParameter(uint16_t t, uint32_t v) {
        data[0] = (t >> 8) & 0xFF;
        data[1] = (t & 0xFF);
        data[2] = (v>>24) & 0xFF;
        data[3] = (v>>16) & 0xFF;
        data[4] = (v>>8) & 0xFF;
        data[5] = (v & 0xFF);
    }

    uint8_t data[6]; // 16-bit SettingsParameterType then 32-bit value.

    uint16_t type() const {return 0 + (data[0]<<8) + data[1];}
    uint32_t value() const {return 0 + (data[2]<<24) + (data[3]<<16) + (data[4]<<8) + data[5];}
};

#if __cplusplus >= 201103L
static_assert(sizeof(struct SettingParameter) == 6, "sizeof(struct SettingParameter) == 6");
#endif

/// a map of SETTINGS values
typedef std::map<uint16_t, uint32_t> SettingsMap;

/// the HTTP/2 specification default SETTINGS values
extern SettingsMap &StdDefaultSettings();

/// Squid-specific default SETTINGS parameters
/// packed in frame payload format ready for delivery.
extern void SquidDefaultSettings(Packable &buf);

} // namespace Two
} // namespace Http

#endif /* _SQUID_SRC_HTTP_TWO_SETTINGS_H */

