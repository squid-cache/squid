/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID__SRC_CONFIGURATION_FORWARD_H
#define _SQUID__SRC_CONFIGURATION_FORWARD_H

/// Squid Configuration management
namespace Configuration
{

/**
 * Limit to how long any given config line may be.
 * This affects squid.conf and all included files.
 *
 * Behaviour when setting larger than 2KB is unknown.
 * The config parser read mechanism can cope, but the other systems
 * receiving the data from its buffers on such lines may not.
 */
#define CONFIG_LINE_LIMIT   2048

class File;

} // namespace Configuration

#endif /* _SQUID__SRC_CONFIGURATION_FORWARD_H */
