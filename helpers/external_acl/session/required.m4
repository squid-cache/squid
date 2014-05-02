AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <db.h>]],[[DB_ENV *db_env = NULL; db_env_create(&db_env, 0);]])],[BUILD_HELPER="session"],[])
