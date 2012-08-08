#include "squid.h"
#include "comm/Connection.h"

#define STUB_API "lmgr/libmgr.la"
#include "tests/STUB.h"

// NP: used by Command.h instantiations
#include "mgr/ActionProfile.h"

// NP: used by Action.h instantiations
#include "mgr/Command.h"
std::ostream &operator <<(std::ostream &os, const Mgr::Command &cmd) STUB_RETVAL(os)

#include "mgr/Action.h"
Mgr::Action::Action(const CommandPointer &aCmd) STUB
Mgr::Action::~Action() STUB
void Mgr::Action::run(StoreEntry *entry, bool writeHttpHeader) STUB
void Mgr::Action::fillEntry(StoreEntry *entry, bool writeHttpHeader) STUB
void Mgr::Action::add(const Action &action) STUB
void Mgr::Action::respond(const Request &request) STUB
void Mgr::Action::sendResponse(unsigned int requestId) STUB
bool Mgr::Action::atomic() const STUB_RETVAL(false)
const char * Mgr::Action::name() const STUB_RETVAL(NULL)
static Mgr::Command static_Command;
const Mgr::Command & Mgr::Action::command() const STUB_RETVAL(static_Command)
StoreEntry * Mgr::Action::createStoreEntry() const STUB_RETVAL(NULL)
static Mgr::Action::Pointer dummyAction;

#include "mgr/ActionParams.h"
Mgr::ActionParams::ActionParams() STUB
Mgr::ActionParams::ActionParams(const Ipc::TypedMsgHdr &msg) STUB
void Mgr::ActionParams::pack(Ipc::TypedMsgHdr &msg) const STUB
std::ostream &operator <<(std::ostream &os, const Mgr::ActionParams &params) STUB_RETVAL(os)

#include "mgr/ActionWriter.h"
//Mgr::ActionWriter::ActionWriter(const Action::Pointer &anAction, int aFd) STUB
//protected:
void Mgr::ActionWriter::start() STUB

#include "mgr/BasicActions.h"
Mgr::Action::Pointer Mgr::MenuAction::Create(const Mgr::CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::MenuAction::dump(StoreEntry *entry) STUB
//protected:
//Mgr::MenuAction::MenuAction(const CommandPointer &cmd) STUB

Mgr::Action::Pointer Mgr::ShutdownAction::Create(const Mgr::CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::ShutdownAction::dump(StoreEntry *entry) STUB
// protected:
//Mgr::ShutdownAction::ShutdownAction(const CommandPointer &cmd) STUB

Mgr::Action::Pointer Mgr::ReconfigureAction::Create(const Mgr::CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::ReconfigureAction::dump(StoreEntry *entry) STUB
//protected:
//Mgr::ReconfigureAction::ReconfigureAction(const CommandPointer &cmd) STUB

Mgr::Action::Pointer Mgr::RotateAction::Create(const Mgr::CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::RotateAction::dump(StoreEntry *entry) STUB
//protected:
//Mgr::RotateAction::RotateAction(const CommandPointer &cmd) STUB

Mgr::Action::Pointer Mgr::OfflineToggleAction::Create(const CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::OfflineToggleAction::dump(StoreEntry *entry) STUB
//protected:
//Mgr::OfflineToggleAction::OfflineToggleAction(const CommandPointer &cmd) STUB

void Mgr::RegisterBasics() STUB

#include "mgr/CountersAction.h"
//Mgr::CountersActionData::CountersActionData() STUB
Mgr::CountersActionData& Mgr::CountersActionData::operator +=(const Mgr::CountersActionData& stats) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::CountersAction::Create(const CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::CountersAction::add(const Action& action) STUB
void Mgr::CountersAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::CountersAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
//protected:
//Mgr::CountersAction::CountersAction(const CommandPointer &cmd) STUB
void Mgr::CountersAction::collect() STUB
void Mgr::CountersAction::dump(StoreEntry* entry) STUB

#include "mgr/Filler.h"
//Mgr::Filler::Filler(const Action::Pointer &anAction, int aFd, unsigned int aRequestId) STUB
//protected:
//void Mgr::Filler::start() STUB
//void Mgr::Filler::swanSong() STUB

#include "mgr/Forwarder.h"
//Mgr::Forwarder::Forwarder(int aFd, const ActionParams &aParams, HttpRequest* aRequest, StoreEntry* anEntry) STUB
//Mgr::Forwarder::~Forwarder() STUB
//protected:
void Mgr::Forwarder::cleanup() STUB
void Mgr::Forwarder::handleError() STUB
void Mgr::Forwarder::handleTimeout() STUB
void Mgr::Forwarder::handleException(const std::exception& e) STUB
void Mgr::Forwarder::handleRemoteAck() STUB

#include "mgr/FunAction.h"
Mgr::Action::Pointer Mgr::FunAction::Create(const CommandPointer &cmd, OBJH *aHandler) STUB_RETVAL(dummyAction)
void Mgr::FunAction::respond(const Request& request) STUB
//protected:
//Mgr::FunAction::FunAction(const CommandPointer &cmd, OBJH *aHandler) STUB
void Mgr::FunAction::dump(StoreEntry *entry) STUB

#include "mgr/InfoAction.h"
//Mgr::InfoActionData::InfoActionData() STUB
Mgr::InfoActionData& Mgr::InfoActionData::operator += (const Mgr::InfoActionData& stats) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::InfoAction::Create(const CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::InfoAction::add(const Action& action) STUB
void Mgr::InfoAction::respond(const Request& request) STUB
void Mgr::InfoAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::InfoAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
//protected:
//Mgr::InfoAction::InfoAction(const Mgr::CommandPointer &cmd) STUB
void Mgr::InfoAction::collect() STUB
void Mgr::InfoAction::dump(StoreEntry* entry) STUB

#include "mgr/Inquirer.h"
//Mgr::Inquirer::Inquirer(Action::Pointer anAction, const Request &aCause, const Ipc::StrandCoords &coords) STUB
//protected:
void Mgr::Inquirer::start() STUB
bool Mgr::Inquirer::doneAll() const STUB_RETVAL(false)
void Mgr::Inquirer::cleanup() STUB
void Mgr::Inquirer::sendResponse() STUB
bool Mgr::Inquirer::aggregate(Ipc::Response::Pointer aResponse) STUB_RETVAL(false)

#include "mgr/IntervalAction.h"
//Mgr::IntervalActionData::IntervalActionData() STUB
Mgr::IntervalActionData& Mgr::IntervalActionData::operator +=(const Mgr::IntervalActionData& stats) STUB_RETVAL(*this)

//Mgr::Action::Pointer Mgr::IntervalAction::Create5min(const CommandPointer &cmd) STUB_RETVAL(new Mgr::IntervalAction(*cmd))
//Mgr::Action::Pointer Mgr::IntervalAction::Create60min(const CommandPointer &cmd) STUB_RETVAL(new Mgr::IntervalAction(*cmd))
void Mgr::IntervalAction::add(const Action& action) STUB
void Mgr::IntervalAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::IntervalAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
//protected:
//Mgr::IntervalAction::IntervalAction(const CommandPointer &cmd, int aMinutes, int aHours) STUB
void Mgr::IntervalAction::collect() STUB
void Mgr::IntervalAction::dump(StoreEntry* entry) STUB

#include "mgr/IntParam.h"
//Mgr::IntParam::IntParam() STUB
//Mgr::IntParam::IntParam(const std::vector<int>& anArray) STUB
void Mgr::IntParam::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::IntParam::unpackValue(const Ipc::TypedMsgHdr& msg) STUB
static std::vector<int> static_vector;
const std::vector<int>& Mgr::IntParam::value() const STUB_RETVAL(static_vector)

#include "mgr/IoAction.h"
//Mgr::IoActionData::IoActionData() STUB
Mgr::IoActionData& Mgr::IoActionData::operator += (const IoActionData& stats) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::IoAction::Create(const CommandPointer &cmd) STUB_RETVAL(dummyAction)
void Mgr::IoAction::add(const Action& action) STUB
void Mgr::IoAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::IoAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
//protected:
//Mgr::IoAction::IoAction(const CommandPointer &cmd) STUB
void Mgr::IoAction::collect() STUB
void Mgr::IoAction::dump(StoreEntry* entry) STUB

//#include "mgr/QueryParam.h"
//void Mgr::QueryParam::pack(Ipc::TypedMsgHdr& msg) const = 0;
//void Mgr::QueryParam::unpackValue(const Ipc::TypedMsgHdr& msg) = 0;

#include "mgr/QueryParams.h"
Mgr::QueryParam::Pointer Mgr::QueryParams::get(const String& name) const STUB_RETVAL(Mgr::QueryParam::Pointer(NULL))
void Mgr::QueryParams::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::QueryParams::unpack(const Ipc::TypedMsgHdr& msg) STUB
bool Mgr::QueryParams::Parse(const String& aParamsStr, QueryParams& aParams) STUB_RETVAL(false)
//private:
//Params::const_iterator Mgr::QueryParams::find(const String& name) const STUB_RETVAL(new Mgr::Params::const_iterator(*this))
Mgr::QueryParam::Pointer Mgr::QueryParams::CreateParam(QueryParam::Type aType) STUB_RETVAL(Mgr::QueryParam::Pointer(NULL))
bool Mgr::QueryParams::ParseParam(const String& paramStr, Param& param) STUB_RETVAL(false)

#include "mgr/Registration.h"
void Mgr::RegisterAction(char const * action, char const * desc, OBJH * handler, int pw_req_flag, int atomic);
void Mgr::RegisterAction(char const * action, char const * desc, ClassActionCreationHandler *handler, int pw_req_flag, int atomic);

#include "mgr/Request.h"
//Mgr::Request::Request(int aRequestorId, unsigned int aRequestId, int aFd, const Mgr::ActionParams &aParams) STUB
//Mgr::Request::Request(const Ipc::TypedMsgHdr& msg) STUB
void Mgr::Request::pack(Ipc::TypedMsgHdr& msg) const STUB
Ipc::Request::Pointer Mgr::Request::clone() const STUB_RETVAL(const_cast<Mgr::Request*>(this))

#include "mgr/Response.h"
//Mgr::Response::Response(unsigned int aRequestId, Action::Pointer anAction = NULL) STUB
//Mgr::Response::Response(const Ipc::TypedMsgHdr& msg) STUB
void Mgr::Response::pack(Ipc::TypedMsgHdr& msg) const STUB
static Ipc::Response::Pointer ipr_static;
Ipc::Response::Pointer Mgr::Response::clone() const STUB_RETVAL(Ipc::Response::Pointer(NULL))
bool Mgr::Response::hasAction() const STUB_RETVAL(false)
//static Mgr::Action mgraction_static;
//const Mgr::Action& Mgr::Response::getAction() const STUB_RETVAL(mgraction_static)

#include "mgr/ServiceTimesAction.h"
//Mgr::ServiceTimesActionData::ServiceTimesActionData() STUB
Mgr::ServiceTimesActionData& Mgr::ServiceTimesActionData::operator +=(const Mgr::ServiceTimesActionData& stats) STUB_RETVAL(*this)

Mgr::Action::Pointer Mgr::ServiceTimesAction::Create(const Mgr::CommandPointer &cmd) STUB_RETVAL(Mgr::Action::Pointer(NULL))
void Mgr::ServiceTimesAction::add(const Action& action) STUB
void Mgr::ServiceTimesAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::ServiceTimesAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
//protected:
//Mgr::ServiceTimesAction::ServiceTimesAction(const CommandPointer &cmd) STUB
void Mgr::ServiceTimesAction::collect() STUB
void Mgr::ServiceTimesAction::dump(StoreEntry* entry) STUB

#include "mgr/StoreIoAction.h"
//Mgr::StoreIoActionData::StoreIoActionData() STUB
Mgr::StoreIoActionData & Mgr::StoreIoActionData::operator +=(const StoreIoActionData& stats) STUB_RETVAL(*this)
//Mgr::StoreIoAction::StoreIoAction(const CommandPointer &cmd) STUB
Mgr::Action::Pointer Mgr::StoreIoAction::Create(const CommandPointer &cmd) STUB_RETVAL(Mgr::Action::Pointer(NULL))
void Mgr::StoreIoAction::add(const Action& action) STUB
void Mgr::StoreIoAction::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::StoreIoAction::unpack(const Ipc::TypedMsgHdr& msg) STUB
void Mgr::StoreIoAction::collect() STUB
void Mgr::StoreIoAction::dump(StoreEntry* entry) STUB

#include "mgr/StoreToCommWriter.h"
//Mgr::StoreToCommWriter::StoreToCommWriter(int aFd, StoreEntry *anEntry) STUB
Mgr::StoreToCommWriter::~StoreToCommWriter() STUB
void Mgr::StoreToCommWriter::start() STUB
void Mgr::StoreToCommWriter::swanSong() STUB
bool Mgr::StoreToCommWriter::doneAll() const STUB_RETVAL(false)
void Mgr::StoreToCommWriter::scheduleStoreCopy() STUB
void Mgr::StoreToCommWriter::noteStoreCopied(StoreIOBuffer ioBuf) STUB
void Mgr::StoreToCommWriter::NoteStoreCopied(void* data, StoreIOBuffer ioBuf) STUB
void Mgr::StoreToCommWriter::Abort(void* param) STUB
void Mgr::StoreToCommWriter::scheduleCommWrite(const StoreIOBuffer& ioBuf) STUB
void Mgr::StoreToCommWriter::noteCommWrote(const CommIoCbParams& params) STUB
void Mgr::StoreToCommWriter::noteCommClosed(const CommCloseCbParams& params) STUB
void Mgr::StoreToCommWriter::close() STUB

#include "mgr/StringParam.h"
//Mgr::StringParam::StringParam() STUB
//Mgr::StringParam::StringParam(const String& aString) STUB
void Mgr::StringParam::pack(Ipc::TypedMsgHdr& msg) const STUB
void Mgr::StringParam::unpackValue(const Ipc::TypedMsgHdr& msg) STUB
static String t;
const String& Mgr::StringParam::value() const STUB_RETVAL(t)
