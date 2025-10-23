/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/*
 * this is a dummy unit test file, meant to be used when a feature
 * is not available to be tested.
 */

#include "squid.h"

int
main() {
    // use this magic return code to inform Automake cfgaux/test-driver
    // that a test was skipped
    return 77;
}

