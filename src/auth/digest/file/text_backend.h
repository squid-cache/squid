/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_AUTH_DIGEST_FILE_TEXT_BACKEND_H
#define SQUID_SRC_AUTH_DIGEST_FILE_TEXT_BACKEND_H

#include "auth/digest/file/digest_common.h"

extern void TextArguments(int argc, char **argv);
extern void TextHHA1(RequestData * requestData);

#endif /* SQUID_SRC_AUTH_DIGEST_FILE_TEXT_BACKEND_H */

