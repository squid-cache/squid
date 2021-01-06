/*
 * Copyright (C) 1996-2020 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "SquidConfig.h"

// TODO: Who is zeroing this global during startup? C++ does not do it for us!
class SquidConfig Config;

class SquidConfig2 Config2;

