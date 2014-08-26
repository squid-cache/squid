#ifndef SQUID_SERVERS_FORWARD_H
#define SQUID_SERVERS_FORWARD_H

class MasterXaction;
template <class C> class RefCount;
typedef RefCount<MasterXaction> MasterXactionPointer;

class ConnStateData;

namespace Http
{

/// create a new HTTP connection handler; never returns NULL
ConnStateData *NewServer(MasterXactionPointer &xact);

} // namespace Http

namespace Https
{

/// create a new HTTPS connection handler; never returns NULL
ConnStateData *NewServer(MasterXactionPointer &xact);

} // namespace Https

namespace Ftp
{

/// accept connections on all configured ftp_ports
void StartListening();
/// reject new connections to any configured ftp_port
void StopListening();

} // namespace Ftp

#endif /* SQUID_SERVERS_FORWARD_H */
