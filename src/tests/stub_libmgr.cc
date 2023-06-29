/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "comm/Connection.h"

#define STUB_API "lmgr/libmgr.la"
#include "tests/STUB.h"

#include "ipc/RequestId.h"

// NP: used by Command.h instantiations
#include "mgr/ActionProfile.h"

// NP: used by Action.h instantiations
#include "mgr/Command.h"
std::ostream &Mgr::operator <<(std::ostream &os, const Command &) STUB_RETVAL(os)

#include "mgr/Action.h"
Mgr::Action::Action(const CommandPointer &) STUB
Mgr::Action::~Action() STUB
void Mgr::Action::run(StoreEntry *, bool) STUB
void Mgr::Action::fillEntry(StoreEntry *, bool) STUB
void Mgr::Action::add(const Action &) STUB
void Mgr::Action::respond(const Request &) STUB
void Mgr::Action::sendResponse(const Ipc::RequestId) STUB
bool Mgr::Action::atomic() const STUB_RETVAL(false)
const char * Mgr::Action::name() const STUB_RETVAL(nullptr)
static Mgr::Command static_Command;
const Mgr::Command & Mgr::Action::command() const STUB_RETVAL(static_Command)
StoreEntry * Mgr::Action::createStoreEntry() const STUB_RETVAL(nullptr)
static Mgr::Action::Pointer dummyAction;

#include "mgr/ActionParams.h"
Mgr::ActionParams::ActionParams() STUB_NOP
Mgr::ActionParams::ActionParams(const Ipc::TypedMsgHdr &) STUB_NOP
void Mgr::ActionParams::pack(Ipc::TypedMsgHdr &) const STUB

#include "mgr/ActionWriter.h"
//Mgr::ActionWriter::ActionWriter(const Action::Pointer &, int) STUB
//protected:
void Mgr::ActionWriter::start() STUB

#include "mgr/BasicActions.h"
Mgr::Action::Pointer Mgr::MenuAction::Create(const Mgr::CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::MenuAction::dump(StoreEntry *) STUB
//protected:
//Mgr::MenuAction::MenuAction(const CommandPointer &cmd) STUB

Mgr::Action::Pointer Mgr::ShutdownAction::Create(const Mgr::CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::ShutdownAction::dump(StoreEntry *) STUB
// protected:
//Mgr::ShutdownAction::ShutdownAction(const CommandPointer &) STUB

Mgr::Action::Pointer Mgr::ReconfigureAction::Create(const Mgr::CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::ReconfigureAction::dump(StoreEntry *) STUB
//protected:
//Mgr::ReconfigureAction::ReconfigureAction(const CommandPointer &) STUB

Mgr::Action::Pointer Mgr::RotateAction::Create(const Mgr::CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::RotateAction::dump(StoreEntry *) STUB
//protected:
//Mgr::RotateAction::RotateAction(const CommandPointer &) STUB

Mgr::Action::Pointer Mgr::OfflineToggleAction::Create(const CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::OfflineToggleAction::dump(StoreEntry *) STUB
//protected:
//Mgr::OfflineToggleAction::OfflineToggleAction(const CommandPointer &) STUB

void Mgr::RegisterBasics() STUB

#include "mgr/CountersAction.h"
//Mgr::CountersActionData::CountersActionData() STUB
Mgr::CountersActionData& Mgr::CountersActionData::operator +=(const Mgr::CountersActionData&) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::CountersAction::Create(const CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::CountersAction::add(const Action &) STUB
void Mgr::CountersAction::pack(Ipc::TypedMsgHdr &) const STUB
void Mgr::CountersAction::unpack(const Ipc::TypedMsgHdr &) STUB
//protected:
//Mgr::CountersAction::CountersAction(const CommandPointer &) STUB
void Mgr::CountersAction::collect() STUB
void Mgr::CountersAction::dump(StoreEntry *) STUB

#include "mgr/Filler.h"
//Mgr::Filler::Filler(const Action::Pointer &, int, unsigned int) STUB
//protected:
//void Mgr::Filler::start() STUB
//void Mgr::Filler::swanSong() STUB

#include "mgr/Forwarder.h"
//Mgr::Forwarder::Forwarder(int, const ActionParams &, HttpRequest *, StoreEntry *) STUB
//Mgr::Forwarder::~Forwarder() STUB
//protected:
//void Mgr::Forwarder::swanSong() STUB
void Mgr::Forwarder::handleError() STUB
void Mgr::Forwarder::handleTimeout() STUB
void Mgr::Forwarder::handleException(const std::exception &) STUB

#include "mgr/FunAction.h"
Mgr::Action::Pointer Mgr::FunAction::Create(const CommandPointer &, OBJH *) STUB_RETVAL(dummyAction)
void Mgr::FunAction::respond(const Request &) STUB
//protected:
//Mgr::FunAction::FunAction(const CommandPointer &, OBJH *) STUB
void Mgr::FunAction::dump(StoreEntry *) STUB

#include "mgr/InfoAction.h"
//Mgr::InfoActionData::InfoActionData() STUB
Mgr::InfoActionData& Mgr::InfoActionData::operator += (const Mgr::InfoActionData &) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::InfoAction::Create(const CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::InfoAction::add(const Action &) STUB
void Mgr::InfoAction::respond(const Request &) STUB
void Mgr::InfoAction::pack(Ipc::TypedMsgHdr &) const STUB
void Mgr::InfoAction::unpack(const Ipc::TypedMsgHdr &) STUB
//protected:
//Mgr::InfoAction::InfoAction(const Mgr::CommandPointer &) STUB
void Mgr::InfoAction::collect() STUB
void Mgr::InfoAction::dump(StoreEntry *) STUB

#include "mgr/Inquirer.h"
//Mgr::Inquirer::Inquirer(Action::Pointer, const Request &, const Ipc::StrandCoords &) STUB
//protected:
void Mgr::Inquirer::start() STUB
bool Mgr::Inquirer::doneAll() const STUB_RETVAL(false)
void Mgr::Inquirer::cleanup() STUB
void Mgr::Inquirer::sendResponse() STUB
bool Mgr::Inquirer::aggregate(Ipc::Response::Pointer) STUB_RETVAL(false)

#include "mgr/IntervalAction.h"
//Mgr::IntervalActionData::IntervalActionData() STUB
Mgr::IntervalActionData& Mgr::IntervalActionData::operator +=(const Mgr::IntervalActionData &) STUB_RETVAL(*this)

//Mgr::Action::Pointer Mgr::IntervalAction::Create5min(const CommandPointer &cmd) STUB_RETVAL(new Mgr::IntervalAction(*cmd))
//Mgr::Action::Pointer Mgr::IntervalAction::Create60min(const CommandPointer &cmd) STUB_RETVAL(new Mgr::IntervalAction(*cmd))
void Mgr::IntervalAction::add(const Action&) STUB
void Mgr::IntervalAction::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::IntervalAction::unpack(const Ipc::TypedMsgHdr&) STUB
//protected:
//Mgr::IntervalAction::IntervalAction(const CommandPointer &, int, int) STUB
void Mgr::IntervalAction::collect() STUB
void Mgr::IntervalAction::dump(StoreEntry*) STUB

#include "mgr/IntParam.h"
//Mgr::IntParam::IntParam() STUB
//Mgr::IntParam::IntParam(const std::vector<int>&) STUB
void Mgr::IntParam::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::IntParam::unpackValue(const Ipc::TypedMsgHdr&) STUB
static std::vector<int> static_vector;
const std::vector<int>& Mgr::IntParam::value() const STUB_RETVAL(static_vector)

#include "mgr/IoAction.h"
//Mgr::IoActionData::IoActionData() STUB
Mgr::IoActionData& Mgr::IoActionData::operator += (const IoActionData&) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::IoAction::Create(const CommandPointer &) STUB_RETVAL(dummyAction)
void Mgr::IoAction::add(const Action&) STUB
void Mgr::IoAction::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::IoAction::unpack(const Ipc::TypedMsgHdr&) STUB
//protected:
//Mgr::IoAction::IoAction(const CommandPointer &) STUB
void Mgr::IoAction::collect() STUB
void Mgr::IoAction::dump(StoreEntry*) STUB

//#include "mgr/QueryParam.h"
//void Mgr::QueryParam::pack(Ipc::TypedMsgHdr&) const = 0;
//void Mgr::QueryParam::unpackValue(const Ipc::TypedMsgHdr&) = 0;

#include "mgr/QueryParams.h"
Mgr::QueryParam::Pointer Mgr::QueryParams::get(const String&) const STUB_RETVAL(Mgr::QueryParam::Pointer(nullptr))
void Mgr::QueryParams::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::QueryParams::unpack(const Ipc::TypedMsgHdr&) STUB
void Mgr::QueryParams::Parse(Parser::Tokenizer &, QueryParams &) STUB
//private:
//Params::const_iterator Mgr::QueryParams::find(const String&) const STUB_RETVAL(new Mgr::Params::const_iterator(*this))
Mgr::QueryParam::Pointer Mgr::QueryParams::CreateParam(QueryParam::Type) STUB_RETVAL(Mgr::QueryParam::Pointer(nullptr))

#include "mgr/Registration.h"
//void Mgr::RegisterAction(char const *, char const *, OBJH *, int, int);
//void Mgr::RegisterAction(char const *, char const *, ClassActionCreationHandler *, int, int);

#include "mgr/Request.h"
//Mgr::Request::Request(int, unsigned int, int, const Mgr::ActionParams &) STUB
//Mgr::Request::Request(const Ipc::TypedMsgHdr&) STUB
void Mgr::Request::pack(Ipc::TypedMsgHdr&) const STUB
Ipc::Request::Pointer Mgr::Request::clone() const STUB_RETVAL(const_cast<Mgr::Request*>(this))

#include "mgr/Response.h"
//Mgr::Response::Response(unsigned int, Action::Pointer) STUB
//Mgr::Response::Response(const Ipc::TypedMsgHdr&) STUB
void Mgr::Response::pack(Ipc::TypedMsgHdr&) const STUB
static Ipc::Response::Pointer ipr_static;
Ipc::Response::Pointer Mgr::Response::clone() const STUB_RETVAL(Ipc::Response::Pointer(nullptr))
bool Mgr::Response::hasAction() const STUB_RETVAL(false)
//static Mgr::Action mgraction_static;
//const Mgr::Action& Mgr::Response::getAction() const STUB_RETVAL(mgraction_static)

#include "mgr/ServiceTimesAction.h"
//Mgr::ServiceTimesActionData::ServiceTimesActionData() STUB
Mgr::ServiceTimesActionData& Mgr::ServiceTimesActionData::operator +=(const Mgr::ServiceTimesActionData&) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::ServiceTimesAction::Create(const Mgr::CommandPointer &) STUB_RETVAL(Mgr::Action::Pointer(nullptr))
void Mgr::ServiceTimesAction::add(const Action&) STUB
void Mgr::ServiceTimesAction::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::ServiceTimesAction::unpack(const Ipc::TypedMsgHdr&) STUB
//protected:
//Mgr::ServiceTimesAction::ServiceTimesAction(const CommandPointer &) STUB
void Mgr::ServiceTimesAction::collect() STUB
void Mgr::ServiceTimesAction::dump(StoreEntry*) STUB

#include "mgr/StoreIoAction.h"
//Mgr::StoreIoActionData::StoreIoActionData() STUB
Mgr::StoreIoActionData & Mgr::StoreIoActionData::operator +=(const StoreIoActionData&) STUB_RETVAL(*this)
//Mgr::StoreIoAction::StoreIoAction(const CommandPointer &) STUB
Mgr::Action::Pointer Mgr::StoreIoAction::Create(const CommandPointer &) STUB_RETVAL(Mgr::Action::Pointer(nullptr))
void Mgr::StoreIoAction::add(const Action&) STUB
void Mgr::StoreIoAction::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::StoreIoAction::unpack(const Ipc::TypedMsgHdr&) STUB
void Mgr::StoreIoAction::collect() STUB
void Mgr::StoreIoAction::dump(StoreEntry*) STUB

#include "mgr/StoreToCommWriter.h"
//Mgr::StoreToCommWriter::StoreToCommWriter(int, StoreEntry *) STUB
Mgr::StoreToCommWriter::~StoreToCommWriter() STUB
void Mgr::StoreToCommWriter::start() STUB
void Mgr::StoreToCommWriter::swanSong() STUB
bool Mgr::StoreToCommWriter::doneAll() const STUB_RETVAL(false)
void Mgr::StoreToCommWriter::scheduleStoreCopy() STUB
void Mgr::StoreToCommWriter::noteStoreCopied(StoreIOBuffer) STUB
void Mgr::StoreToCommWriter::NoteStoreCopied(void*, StoreIOBuffer) STUB
void Mgr::StoreToCommWriter::HandleStoreAbort(StoreToCommWriter *) STUB
void Mgr::StoreToCommWriter::scheduleCommWrite(const StoreIOBuffer&) STUB
void Mgr::StoreToCommWriter::noteCommWrote(const CommIoCbParams&) STUB
void Mgr::StoreToCommWriter::noteCommClosed(const CommCloseCbParams&) STUB
void Mgr::StoreToCommWriter::close() STUB

#include "mgr/StringParam.h"
//Mgr::StringParam::StringParam() STUB
//Mgr::StringParam::StringParam(const String&) STUB
void Mgr::StringParam::pack(Ipc::TypedMsgHdr&) const STUB
void Mgr::StringParam::unpackValue(const Ipc::TypedMsgHdr&) STUB
static String t;
const String& Mgr::StringParam::value() const STUB_RETVAL(t)

