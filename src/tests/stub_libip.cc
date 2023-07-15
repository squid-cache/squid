/*
 * Copyright (C) 1996-2023 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "Store.h"

#define STUB_API "ip/libip.la"
#include "tests/STUB.h"

#include "ip/Address.h"
Ip::Address::Address(const struct in_addr &) STUB
Ip::Address::Address(const struct sockaddr_in &) STUB
Ip::Address::Address(const struct in6_addr &) STUB
Ip::Address::Address(const struct sockaddr_in6 &) STUB
Ip::Address::Address(const struct hostent &) STUB
Ip::Address::Address(const struct addrinfo &) STUB
Ip::Address::Address(const char*) STUB
Ip::Address& Ip::Address::operator =(struct sockaddr_in const &) STUB_RETVAL(*this)
Ip::Address& Ip::Address::operator =(struct sockaddr_storage const &) STUB_RETVAL(*this)
Ip::Address& Ip::Address::operator =(struct in_addr const &) STUB_RETVAL(*this)
Ip::Address& Ip::Address::operator =(struct in6_addr const &) STUB_RETVAL(*this)
Ip::Address& Ip::Address::operator =(struct sockaddr_in6 const &) STUB_RETVAL(*this)
bool Ip::Address::operator =(const struct hostent &) STUB_RETVAL(false)
bool Ip::Address::operator =(const struct addrinfo &) STUB_RETVAL(false)
bool Ip::Address::operator =(const char *) STUB_RETVAL(false)
bool Ip::Address::operator ==(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::operator !=(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::operator >=(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::operator <=(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::operator >(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::operator <(Ip::Address const &) const STUB_RETVAL(false)
bool Ip::Address::isIPv4() const STUB_RETVAL(false)
bool Ip::Address::isIPv6() const STUB_RETVAL(false)
bool Ip::Address::isSockAddr() const STUB_RETVAL(false)
bool Ip::Address::isAnyAddr() const STUB_RETVAL(false)
bool Ip::Address::isNoAddr() const STUB_RETVAL(false)
bool Ip::Address::isLocalhost() const STUB_RETVAL(false)
bool Ip::Address::isSiteLocal6() const STUB_RETVAL(false)
bool Ip::Address::isSiteLocalAuto() const STUB_RETVAL(false)
unsigned short Ip::Address::port() const STUB
unsigned short Ip::Address::port(unsigned short) STUB
void Ip::Address::setAnyAddr() STUB
void Ip::Address::setNoAddr() STUB
void Ip::Address::setLocalhost() STUB
void Ip::Address::setEmpty() STUB_NOP // NOP for default constructor
bool Ip::Address::setIPv4() STUB_RETVAL(false)
int Ip::Address::cidr() const STUB_RETVAL(0)
int Ip::Address::applyMask(const Ip::Address &) STUB_RETVAL(0)
bool Ip::Address::applyMask(const unsigned int, int) STUB_RETVAL(false)
void Ip::Address::applyClientMask(const Ip::Address &) STUB
char* Ip::Address::toStr(char *, const unsigned int, int) const STUB_RETVAL(nullptr)
char* Ip::Address::toUrl(char *, unsigned int) const STUB_RETVAL(nullptr)
unsigned int Ip::Address::toHostStr(char *, const unsigned int) const STUB_RETVAL(0)
bool Ip::Address::fromHost(const char *) STUB_RETVAL(false)
bool Ip::Address::getReverseString(char [MAX_IPSTRLEN], int) const STUB_RETVAL(false)
int Ip::Address::matchIPAddr(const Ip::Address &) const STUB_RETVAL(0)
int Ip::Address::compareWhole(const Ip::Address &) const STUB_RETVAL(0)
void Ip::Address::getAddrInfo(struct addrinfo *&, int) const STUB
void Ip::Address::FreeAddr(struct addrinfo *&) STUB
void Ip::Address::InitAddr(struct addrinfo *&) STUB
bool Ip::Address::GetHostByName(const char *) STUB_RETVAL(false)
void Ip::Address::getSockAddr(struct sockaddr_storage &, const int) const STUB
void Ip::Address::getSockAddr(struct sockaddr_in &) const STUB
bool Ip::Address::getInAddr(struct in_addr &) const STUB_RETVAL(false)
void Ip::Address::getSockAddr(struct sockaddr_in6 &) const STUB
void Ip::Address::getInAddr(struct in6_addr &) const STUB
void parse_IpAddress_list_token(Ip::Address_list **, char *) STUB

//#include "ip/forward.h"

#include "ip/QosConfig.h"
CBDATA_CLASS_INIT(acl_tos);
acl_tos::~acl_tos() STUB
CBDATA_CLASS_INIT(acl_nfmark);
acl_nfmark::~acl_nfmark() STUB
void Ip::Qos::getTosFromServer(const Comm::ConnectionPointer &, fde *) STUB
nfmark_t Ip::Qos::getNfConnmark(const Comm::ConnectionPointer &, const ConnectionDirection) STUB_RETVAL(-1)
bool Ip::Qos::setNfConnmark(Comm::ConnectionPointer &, const ConnectionDirection, const Ip::NfMarkConfig &) STUB_RETVAL(false)
int Ip::Qos::doTosLocalMiss(const Comm::ConnectionPointer &, const hier_code) STUB_RETVAL(-1)
int Ip::Qos::doNfmarkLocalMiss(const Comm::ConnectionPointer &, const hier_code) STUB_RETVAL(-1)
int Ip::Qos::doTosLocalHit(const Comm::ConnectionPointer &) STUB_RETVAL(-1)
int Ip::Qos::doNfmarkLocalHit(const Comm::ConnectionPointer &) STUB_RETVAL(-1)
int Ip::Qos::setSockTos(const Comm::ConnectionPointer &, tos_t) STUB_RETVAL(-1)
int Ip::Qos::setSockTos(const int, tos_t, int) STUB_RETVAL(-1)
int Ip::Qos::setSockNfmark(const Comm::ConnectionPointer &, nfmark_t) STUB_RETVAL(-1)
int Ip::Qos::setSockNfmark(const int, nfmark_t) STUB_RETVAL(-1)
Ip::Qos::Config::Config() STUB_NOP
void Ip::Qos::Config::parseConfigLine() STUB
void Ip::Qos::Config::dumpConfigLine(char *, const char *) const STUB
bool Ip::Qos::Config::isAclNfmarkActive() const STUB_RETVAL(false)
bool Ip::Qos::Config::isAclTosActive() const STUB_RETVAL(false)
Ip::Qos::Config Ip::Qos::TheConfig;

#include "ip/Intercept.h"
bool Ip::Intercept::LookupNat(const Comm::Connection &) STUB_RETVAL(false)
bool Ip::Intercept::ProbeForTproxy(Ip::Address &) STUB_RETVAL(false)
void Ip::Intercept::StartTransparency() STUB
void Ip::Intercept::StopTransparency(const char *) STUB
void Ip::Intercept::StartInterception() STUB
Ip::Intercept Ip::Interceptor;

#include "ip/NfMarkConfig.h"
Ip::NfMarkConfig Ip::NfMarkConfig::Parse(const SBuf &) STUB_RETSTATREF(Ip::NfMarkConfig)
nfmark_t Ip::NfMarkConfig::applyToMark(nfmark_t) const STUB_RETVAL(0)
std::ostream &Ip::operator <<(std::ostream &os, Ip::NfMarkConfig) STUB_RETVAL(os)

#include "ip/tools.h"
void Ip::ProbeTransport() STUB
int Ip::EnableIpv6 = 0;

