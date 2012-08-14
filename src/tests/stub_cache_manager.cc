#include "squid.h"
#include "CacheManager.h"
#include "Debug.h"
#include "mgr/Registration.h"

#define STUB_API "cache_manager.cc"
#include "tests/STUB.h"

Mgr::Action::Pointer CacheManager::createNamedAction(char const* action) STUB_RETVAL(NULL)
void CacheManager::Start(const Comm::ConnectionPointer &conn, HttpRequest * request, StoreEntry * entry)
{
    std::cerr << HERE << "\n";
    STUB
}
CacheManager* CacheManager::instance=0;
CacheManager* CacheManager::GetInstance() STUB_RETVAL(instance)
void Mgr::RegisterAction(char const*, char const*, OBJH, int, int) {}
void Mgr::RegisterAction(char const *, char const *, Mgr::ClassActionCreationHandler *, int, int) {}
