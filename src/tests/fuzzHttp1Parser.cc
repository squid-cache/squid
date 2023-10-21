/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#include "compat/cppunit.h"
#include "debug/Stream.h"
#include "http/one/RequestParser.h"
#include "http/RequestMethod.h"
#include "MemBuf.h"
#include "SquidConfig.h"

#define kMinInputLength 10
#define kMaxInputLength 5120

static bool setup_done = false;

extern "C" int LLVMFuzzerTestOneInput(const char *data, size_t size)
{

    if (size < kMinInputLength || size > kMaxInputLength) {
        return 0;
    }

    if (!setup_done){
        Mem::Init();
        setup_done = true;

        // default to strict parser. set for loose parsing specifically where behaviour differs.
        Config.onoff.relaxed_header_parser = 0;

        Config.maxRequestHeaderSize = 1024; // XXX: unit test the RequestParser handling of this limit
    }

    SBuf ioBuf;
    Http1::RequestParser hp;

    ioBuf.clear();
    ioBuf.append(data, size);

    hp.clear();
    hp.parse(ioBuf);

    return 0;
}
