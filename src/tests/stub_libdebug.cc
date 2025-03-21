/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"

#define STUB_API "debug/libdebug.la"
#include "tests/STUB.h"

#include "debug/Messages.h"

#include "debug/Stream.h"
Debug::Context::Context(const int, const int) : section(0), level(0), sectionLevel(0) {STUB}
char *Debug::debugOptions = nullptr;
char *Debug::cache_log = nullptr;
int Debug::rotateNumber = 0;
int Debug::Levels[MAX_DEBUG_SECTIONS] = {};
int Debug::override_X = 0;
bool Debug::log_syslog = false;
void Debug::NameThisHelper(const char *) STUB
void Debug::NameThisKid(int) STUB
void Debug::parseOptions(char const *) STUB
static std::ostringstream nilStream;
std::ostringstream &Debug::Start(const int, const int) STUB_RETVAL_NOP(nilStream)
void Debug::Finish() STUB_NOP
void Debug::ForceAlert() STUB
std::ostream& Debug::Extra(std::ostream &s) STUB_RETVAL(s)
void Debug::ForgetSaved() STUB
void Debug::PrepareToDie() STUB
void Debug::LogWaitingForIdle() STUB
void Debug::BanCacheLogUse() STUB
void Debug::UseCacheLog() STUB
void Debug::StopCacheLogUse() STUB
void Debug::EnsureDefaultStderrLevel(int) STUB
void Debug::ResetStderrLevel(int) STUB
void Debug::SettleStderr() STUB
bool Debug::StderrEnabled() STUB_RETVAL(false);
void Debug::ConfigureSyslog(const char *) STUB
void Debug::SettleSyslog() STUB
Debug::Context *Debug::Current = nullptr;
FILE *DebugStream() STUB_RETVAL(nullptr)
void ResyncDebugLog(FILE *) STUB_NOP
std::ostream & ForceAlert(std::ostream &s) STUB_RETVAL_NOP(s)
void _db_rotate_log() STUB_NOP
