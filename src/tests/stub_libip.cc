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
namespace Ip
{
Address::Address(const struct in_addr &) STUB
Address::Address(const struct sockaddr_in &) STUB
Address::Address(const struct in6_addr &) STUB
Address::Address(const struct sockaddr_in6 &) STUB
Address::Address(const struct hostent &) STUB
Address::Address(const struct addrinfo &) STUB
Address::Address(const char*) STUB
Address& Address::operator =(struct sockaddr_in const &) STUB_RETVAL(*this)
Address& Address::operator =(struct sockaddr_storage const &) STUB_RETVAL(*this)
Address& Address::operator =(struct in_addr const &) STUB_RETVAL(*this)
Address& Address::operator =(struct in6_addr const &) STUB_RETVAL(*this)
Address& Address::operator =(struct sockaddr_in6 const &) STUB_RETVAL(*this)
bool Address::operator =(const struct hostent &) STUB_RETVAL(false)
bool Address::operator =(const struct addrinfo &) STUB_RETVAL(false)
bool Address::operator =(const char *) STUB_RETVAL(false)
bool Address::operator ==(Address const &) const STUB_RETVAL(false)
bool Address::operator !=(Address const &) const STUB_RETVAL(false)
bool Address::operator >=(Address const &) const STUB_RETVAL(false)
bool Address::operator <=(Address const &) const STUB_RETVAL(false)
bool Address::operator >(Address const &) const STUB_RETVAL(false)
bool Address::operator <(Address const &) const STUB_RETVAL(false)
bool Address::isIPv4() const STUB_RETVAL(false)
bool Address::isIPv6() const STUB_RETVAL(false)
bool Address::isSockAddr() const STUB_RETVAL(false)
bool Address::isAnyAddr() const STUB_RETVAL(false)
bool Address::isNoAddr() const STUB_RETVAL(false)
bool Address::isLocalhost() const STUB_RETVAL(false)
bool Address::isSiteLocal6() const STUB_RETVAL(false)
bool Address::isSiteLocalAuto() const STUB_RETVAL(false)
unsigned short Address::port() const STUB
unsigned short Address::port(unsigned short) STUB
void Address::setAnyAddr() STUB
void Address::setNoAddr() STUB
void Address::setLocalhost() STUB
void Address::setEmpty() STUB_NOP // NOP for default constructor
bool Address::setIPv4() STUB_RETVAL(false)
int Address::cidr() const STUB_RETVAL(0)
int Address::applyMask(const Address &) STUB_RETVAL(0)
bool Address::applyMask(const unsigned int, int) STUB_RETVAL(false)
void Address::applyClientMask(const Address &) STUB
char* Address::toStr(char *, const unsigned int, int) const STUB_RETVAL(nullptr)
char* Address::toUrl(char *, unsigned int) const STUB_RETVAL(nullptr)
unsigned int Address::toHostStr(char *, const unsigned int) const STUB_RETVAL(0)
bool Address::fromHost(const char *) STUB_RETVAL(false)
bool Address::getReverseString(char [], int) const STUB_RETVAL(false)
int Address::matchIPAddr(const Address &) const STUB_RETVAL(0)
int Address::compareWhole(const Ip::Address &) const STUB_RETVAL(0)
void Address::getAddrInfo(struct addrinfo *&, int) const STUB
void Address::FreeAddr(struct addrinfo *&) STUB
void Address::InitAddr(struct addrinfo *&) STUB
bool Address::GetHostByName(const char *) STUB_RETVAL(false)
void Address::getSockAddr(struct sockaddr_storage &, const int) const STUB
void Address::getSockAddr(struct sockaddr_in &) const STUB
bool Address::getInAddr(struct in_addr &) const STUB_RETVAL(false)
void Address::getSockAddr(struct sockaddr_in6 &) const STUB
void Address::getInAddr(struct in6_addr &) const STUB
} // namespace Ip
void parse_IpAddress_list_token(Ip::Address_list **, char *) STUB

//#include "ip/forward.h"

#include "ip/QosConfig.h"
CBDATA_CLASS_INIT(acl_tos);
acl_tos::~acl_tos() STUB
CBDATA_CLASS_INIT(acl_nfmark);
acl_nfmark::~acl_nfmark() STUB
namespace Ip
{
namespace Qos
{
void getTosFromServer(const Comm::ConnectionPointer &, fde *) STUB
nfmark_t getNfConnmark(const Comm::ConnectionPointer &, const ConnectionDirection) STUB_RETVAL(-1)
bool setNfConnmark(Comm::ConnectionPointer &, const ConnectionDirection, const NfMarkConfig &) STUB_RETVAL(false)
int doTosLocalMiss(const Comm::ConnectionPointer &, const hier_code) STUB_RETVAL(-1)
int doNfmarkLocalMiss(const Comm::ConnectionPointer &, const hier_code) STUB_RETVAL(-1)
int doTosLocalHit(const Comm::ConnectionPointer &) STUB_RETVAL(-1)
int doNfmarkLocalHit(const Comm::ConnectionPointer &) STUB_RETVAL(-1)
int setSockTos(const Comm::ConnectionPointer &, tos_t) STUB_RETVAL(-1)
int setSockTos(const int, tos_t, int) STUB_RETVAL(-1)
int setSockNfmark(const Comm::ConnectionPointer &, nfmark_t) STUB_RETVAL(-1)
int setSockNfmark(const int, nfmark_t) STUB_RETVAL(-1)
Config::Config() STUB_NOP
void Config::parseConfigLine() STUB
void Config::dumpConfigLine(char *, const char *) const STUB
bool Config::isAclNfmarkActive() const STUB_RETVAL(false)
bool Config::isAclTosActive() const STUB_RETVAL(false)
Config TheConfig;
} // namespace Qos
} // namespace Ip

#include "ip/Intercept.h"
namespace Ip
{
bool Intercept::LookupNat(const Comm::Connection &) STUB_RETVAL(false)
bool Intercept::ProbeForTproxy(Address &) STUB_RETVAL(false)
void Intercept::StartTransparency() STUB
void Intercept::StopTransparency(const char *) STUB
void Intercept::StartInterception() STUB
Intercept Interceptor;
} // namespace Ip

#include "ip/NfMarkConfig.h"
namespace Ip
{
NfMarkConfig NfMarkConfig::Parse(const SBuf &) STUB_RETSTATREF(NfMarkConfig)
nfmark_t NfMarkConfig::applyToMark(nfmark_t) const STUB_RETVAL(0)
std::ostream &operator <<(std::ostream &os, NfMarkConfig) STUB_RETVAL(os)
} // namespace Ip

#include "ip/tools.h"
namespace Ip
{
void ProbeTransport() STUB
int EnableIpv6 = 0;
} // namespace Ip

