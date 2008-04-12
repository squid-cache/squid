
/*
 * $Id: WinSvc.cc,v 1.3.4.2 2008/02/17 19:28:18 serassio Exp $
 *
 * Windows support
 * AUTHOR: Guido Serassio <serassio@squid-cache.org>
 * inspired by previous work by Romeo Anghelache & Eric Stern.
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include "squid_windows.h"

#ifdef _SQUID_MSWIN_
#ifndef _MSWSOCK_
#include <mswsock.h>
#endif
#include <process.h>
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
#include <crtdbg.h>
#endif
#endif

static unsigned int GetOSVersion();
void WIN32_svcstatusupdate(DWORD, DWORD);
void WINAPI WIN32_svcHandler(DWORD);
#if USE_WIN32_SERVICE
static int WIN32_StoreKey(const char *, DWORD, unsigned char *, int);
static int WIN32_create_key(void);
static void WIN32_build_argv (char *);
#endif
extern "C" void WINAPI SquidWinSvcMain(DWORD, char **);

#if defined(_SQUID_MSWIN_)
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
void Squid_Win32InvalidParameterHandler(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t);
#endif
static int Win32SockInit(void);
static void Win32SockCleanup(void);
SQUIDCEXTERN LPCRITICAL_SECTION dbg_mutex;
void WIN32_ExceptionHandlerCleanup(void);
static int s_iInitCount = 0;
#endif

static int Squid_Aborting = 0;
static HANDLE NotifyAddrChange_thread = INVALID_HANDLE_VALUE;

#undef NotifyAddrChange
typedef DWORD(WINAPI * PFNotifyAddrChange) (OUT PHANDLE, IN LPOVERLAPPED);
#define NOTIFYADDRCHANGE "NotifyAddrChange"

#if USE_WIN32_SERVICE
static SERVICE_STATUS svcStatus;
static SERVICE_STATUS_HANDLE svcHandle;
static int WIN32_argc;
static char ** WIN32_argv;
static char * WIN32_module_name;

#define VENDOR "GNU"
static char VENDORString[] = VENDOR;
#define SOFTWARENAME "Squid"
static char SOFTWARENAMEString[] = SOFTWARENAME;
#define WIN32_VERSION "3.0"
static char WIN32_VERSIONString[] = WIN32_VERSION;
#define SOFTWARE "SOFTWARE"
static char SOFTWAREString[] = SOFTWARE;
#define COMMANDLINE "CommandLine"
#define CONFIGFILE  "ConfigFile"
#undef ChangeServiceConfig2
typedef BOOL (WINAPI * PFChangeServiceConfig2) (SC_HANDLE, DWORD, LPVOID);
#ifdef UNICODE
#define CHANGESERVICECONFIG2 "ChangeServiceConfig2W"
#else
#define CHANGESERVICECONFIG2 "ChangeServiceConfig2A"
#endif
static SC_ACTION Squid_SCAction[] = { { SC_ACTION_RESTART, 60000 } };
static char Squid_ServiceDescriptionString[] = SOFTWARENAME " " VERSION " WWW Proxy Server";
static SERVICE_DESCRIPTION Squid_ServiceDescription = { Squid_ServiceDescriptionString };
static SERVICE_FAILURE_ACTIONS Squid_ServiceFailureActions = { INFINITE, NULL, NULL, 1, Squid_SCAction };
static char REGKEY[256]=SOFTWARE"\\"VENDOR"\\"SOFTWARENAME"\\"WIN32_VERSION"\\";
static char *keys[] = {
                          SOFTWAREString,	    /* key[0] */
                          VENDORString,	    /* key[1] */
                          SOFTWARENAMEString,   /* key[2] */
                          WIN32_VERSIONString,  /* key[3] */
                          NULL,	    /* key[4] */
                          NULL	    /* key[5] */
                      };
#endif

/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

#if USE_WIN32_SERVICE
static int
WIN32_create_key(void)
{
    int index;
    HKEY hKey;
    HKEY hKeyNext;
    int retval;
    LONG rv;

    hKey = HKEY_LOCAL_MACHINE;
    index = 0;
    retval = 0;

    /* Walk the tree, creating at each stage if necessary */

    while (keys[index]) {
        unsigned long result;
        rv = RegCreateKeyEx(hKey, keys[index],	/* subkey */
                            0,			/* reserved */
                            NULL,		/* class */
                            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKeyNext, &result);

        if (rv != ERROR_SUCCESS) {
            fprintf(stderr, "RegCreateKeyEx(%s),%d\n", keys[index], (int) rv);
            retval = -4;
        }

        /* Close the old key */
        rv = RegCloseKey(hKey);

        if (rv != ERROR_SUCCESS) {
            fprintf(stderr, "RegCloseKey %d\n", (int) rv);

            if (retval == 0) {
                /* Keep error status from RegCreateKeyEx, if any */
                retval = -4;
            }
        }

        if (retval) {
            break;
        }

        hKey = hKeyNext;
        index++;
    }

    if (keys[index] == NULL) {
        /* Close the final key we opened, if we walked the entire
         * tree
         */
        rv = RegCloseKey(hKey);

        if (rv != ERROR_SUCCESS) {
            fprintf(stderr, "RegCloseKey %d\n", (int) rv);

            if (retval == 0) {
                /* Keep error status from RegCreateKeyEx, if any */
                retval = -4;
            }
        }
    }

    return retval;
}

static int
WIN32_StoreKey(const char *key, DWORD type, unsigned char *value,
               int value_size)
{
    LONG rv;
    HKEY hKey;
    int retval;

    rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGKEY, 0, KEY_WRITE, &hKey);

    if (rv == ERROR_FILE_NOT_FOUND) {
        /* Key could not be opened -- try to create it
         */

        if (WIN32_create_key() < 0) {
            /* Creation failed (error already reported) */
            return -4;
        }

        /* Now it has been created we should be able to open it
         */
        rv = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGKEY, 0, KEY_WRITE, &hKey);

        if (rv == ERROR_FILE_NOT_FOUND) {
            fprintf(stderr, "Registry does not contain key %s after creation\n",
                    REGKEY);
            return -1;
        }
    }

    if (rv != ERROR_SUCCESS) {
        fprintf(stderr, "RegOpenKeyEx HKLM\\%s, %d\n", REGKEY, (int) rv);
        return -4;
    }

    /* Now set the value and data */
    rv = RegSetValueEx(hKey, key,	/* value key name */
                       0,			/* reserved */
                       type,			/* type */
                       value,			/* value data */
                       (DWORD) value_size);	/* for size of "value" */

    retval = 0;			/* Return value */

    if (rv != ERROR_SUCCESS) {
        fprintf(stderr, "RegQueryValueEx(key %s),%d\n", key, (int) rv);
        retval = -4;
    } else {
        fprintf(stderr, "Registry stored HKLM\\%s\\%s value %s\n",
                REGKEY,
                key,
                type == REG_SZ ? value : (unsigned char *) "(not displayable)");
    }

    /* Make sure we close the key even if there was an error storing
     * the data
     */
    rv = RegCloseKey(hKey);

    if (rv != ERROR_SUCCESS) {
        fprintf(stderr, "RegCloseKey HKLM\\%s, %d\n", REGKEY, (int) rv);

        if (retval == 0) {
            /* Keep error status from RegQueryValueEx, if any */
            retval = -4;
        }
    }

    return retval;
}

/* Build argv, argc from string passed from Windows.  */
static void WIN32_build_argv(char *cmd)
{
    int argvlen = 0;
    char *word;

    WIN32_argc = 1;
    WIN32_argv = (char **) xmalloc ((WIN32_argc+1) * sizeof (char *));
    WIN32_argv[0]=xstrdup(WIN32_module_name);
    /* Scan command line until there is nothing left. */

    while (*cmd) {
        /* Ignore spaces */

        if (xisspace(*cmd)) {
            cmd++;
            continue;
        }

        /* Found the beginning of an argument. */
        word = cmd;

        while (*cmd) {
            cmd++;		/* Skip over this character */

            if (xisspace(*cmd))	/* End of argument if space */
                break;
        }

        if (*cmd)
            *cmd++ = '\0';		/* Terminate `word' */

        /* See if we need to allocate more space for argv */
        if (WIN32_argc >= argvlen) {
            argvlen = WIN32_argc + 1;
            WIN32_argv = (char **) xrealloc (WIN32_argv, (1 + argvlen) * sizeof (char *));
        }

        /* Add word to argv file. */
        WIN32_argv[WIN32_argc++] = word;
    }

    WIN32_argv[WIN32_argc] = NULL;
}

#endif /* USE_WIN32_SERVICE */

static unsigned int
GetOSVersion()
{
    OSVERSIONINFOEX osvi;
    BOOL bOsVersionInfoEx;

    safe_free(WIN32_OS_string);
    memset(&osvi, '\0', sizeof(OSVERSIONINFOEX));
    /* Try calling GetVersionEx using the OSVERSIONINFOEX structure.
     * If that fails, try using the OSVERSIONINFO structure.
     */

    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!(bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *) & osvi))) {
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	if (!GetVersionEx((OSVERSIONINFO *) & osvi))
	    goto GetVerError;
    }
    switch (osvi.dwPlatformId) {
    case VER_PLATFORM_WIN32_NT:
	if (osvi.dwMajorVersion <= 4) {
	    WIN32_OS_string = xstrdup("Windows NT");
	    return _WIN_OS_WINNT;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 0)) {
	    WIN32_OS_string = xstrdup("Windows 2000");
	    return _WIN_OS_WIN2K;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 1)) {
	    WIN32_OS_string = xstrdup("Windows XP");
	    return _WIN_OS_WINXP;
	}
	if ((osvi.dwMajorVersion == 5) && (osvi.dwMinorVersion == 2)) {
	    WIN32_OS_string = xstrdup("Windows Server 2003");
	    return _WIN_OS_WINNET;
	}
	if ((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion == 0)) {
	    if (osvi.wProductType == VER_NT_WORKSTATION)
		WIN32_OS_string = xstrdup("Windows Vista");
	    else
		WIN32_OS_string = xstrdup("Windows Server 2008");
	    return _WIN_OS_WINLON;
	}
	break;
    case VER_PLATFORM_WIN32_WINDOWS:
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 0)) {
	    WIN32_OS_string = xstrdup("Windows 95");
	    return _WIN_OS_WIN95;
	}
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 10)) {
	    WIN32_OS_string = xstrdup("Windows 98");
	    return _WIN_OS_WIN98;
	}
	if ((osvi.dwMajorVersion == 4) && (osvi.dwMinorVersion == 90)) {
	    WIN32_OS_string = xstrdup("Windows Me");
	    return _WIN_OS_WINME;
	}
	break;
    case VER_PLATFORM_WIN32s:
	WIN32_OS_string = xstrdup("Windows 3.1 with WIN32S");
	return _WIN_OS_WIN32S;
	break;
    default:
	break;
    }
  GetVerError:
    WIN32_OS_string = xstrdup("Unknown Windows system");
    return _WIN_OS_UNKNOWN;
}

/* ====================================================================== */
/* PUBLIC FUNCTIONS */
/* ====================================================================== */

void
WIN32_Abort(int sig)
{
#if USE_WIN32_SERVICE
    svcStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    svcStatus.dwServiceSpecificExitCode = 1;
#endif

    Squid_Aborting = 1;
    WIN32_Exit();
}

void
WIN32_IpAddrChangeMonitorExit()
{
    DWORD status = ERROR_SUCCESS;

    if (NotifyAddrChange_thread == INVALID_HANDLE_VALUE) {
	TerminateThread(NotifyAddrChange_thread, status);
	CloseHandle(NotifyAddrChange_thread);
    }
}

void
WIN32_Exit()
{
#ifdef _SQUID_MSWIN_
    Win32SockCleanup();
#endif
#if USE_WIN32_SERVICE

    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        if (!Squid_Aborting) {
            svcStatus.dwCurrentState = SERVICE_STOPPED;
            SetServiceStatus(svcHandle, &svcStatus);
        }
    }

#endif
#ifdef _SQUID_MSWIN_
    if (dbg_mutex)
        DeleteCriticalSection(dbg_mutex);

    WIN32_ExceptionHandlerCleanup();
    WIN32_IpAddrChangeMonitorExit();

#endif

    _exit(0);
}

#ifdef _SQUID_MSWIN_
static DWORD WINAPI
WIN32_IpAddrChangeMonitor(LPVOID lpParam)
{
    DWORD Result;
    HMODULE IPHLPAPIHandle;
    PFNotifyAddrChange NotifyAddrChange;

    if ((IPHLPAPIHandle = GetModuleHandle("IPHLPAPI")) == NULL)
	IPHLPAPIHandle = LoadLibrary("IPHLPAPI");
    NotifyAddrChange = (PFNotifyAddrChange) GetProcAddress(IPHLPAPIHandle, NOTIFYADDRCHANGE);

    while (1) {
	Result = NotifyAddrChange(NULL, NULL);
	if (Result != NO_ERROR) {
	    debugs(1, 1, "NotifyAddrChange error " << Result);
	    return 1;
	}
	debugs(1, 1, "Notification of IP address change received, requesting Squid reconfiguration ...");
	reconfigure(SIGHUP);
    }
    return 0;
}

DWORD
WIN32_IpAddrChangeMonitorInit()
{
    DWORD status = ERROR_SUCCESS;
    DWORD threadID = 0, ThrdParam = 0;

    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
	NotifyAddrChange_thread = CreateThread(NULL, 0, WIN32_IpAddrChangeMonitor,
	    &ThrdParam, 0, &threadID);
	if (NotifyAddrChange_thread == NULL) {
	    status = GetLastError();
	    NotifyAddrChange_thread = INVALID_HANDLE_VALUE;
	    debugs(1, 1, "Failed to start IP monitor thread.");
	} else
	    debugs(1, 2, "Starting IP monitor thread [" << threadID << "] ...");
    }
    return status;
}
#endif

int WIN32_Subsystem_Init(int * argc, char *** argv)
{
#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */
    _invalid_parameter_handler oldHandler, newHandler;
#endif

    WIN32_OS_version = GetOSVersion();

    if ((WIN32_OS_version == _WIN_OS_UNKNOWN) || (WIN32_OS_version == _WIN_OS_WIN32S))
        return 1;

    if (atexit(WIN32_Exit) != 0)
        return 1;

#if defined(_MSC_VER) /* Microsoft C Compiler ONLY */

    newHandler = Squid_Win32InvalidParameterHandler;

    oldHandler = _set_invalid_parameter_handler(newHandler);

    _CrtSetReportMode(_CRT_ASSERT, 0);

#endif
#if USE_WIN32_SERVICE

    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        char path[512];
        HKEY hndKey;

        if (signal(SIGABRT, WIN32_Abort) == SIG_ERR)
            return 1;

        /* Register the service Handler function */
        svcHandle =
            RegisterServiceCtrlHandler(WIN32_Service_name,
                                       WIN32_svcHandler);

        if (svcHandle == 0)
            return 1;

        /* Set Process work dir to directory cointaining squid.exe */
        GetModuleFileName(NULL, path, 512);

        WIN32_module_name=xstrdup(path);

        path[strlen(path) - 10] = '\0';

        if (SetCurrentDirectory(path) == 0)
            return 1;

        safe_free(ConfigFile);

        /* get config file from Windows Registry */
        if (RegOpenKey(HKEY_LOCAL_MACHINE, REGKEY, &hndKey) == ERROR_SUCCESS) {
            DWORD Type = 0;
            DWORD Size = 0;
            LONG Result;
            Result =
                RegQueryValueEx(hndKey, CONFIGFILE, NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                ConfigFile = static_cast<char *>(xmalloc(Size));
                RegQueryValueEx(hndKey, CONFIGFILE, NULL, &Type, (unsigned char *)ConfigFile,
                                &Size);
            } else
                ConfigFile = xstrdup(DefaultConfigFile);

            Size = 0;

            Type = 0;

            Result =
                RegQueryValueEx(hndKey, COMMANDLINE, NULL, &Type, NULL, &Size);

            if (Result == ERROR_SUCCESS && Size) {
                WIN32_Service_Command_Line = static_cast<char *>(xmalloc(Size));
                RegQueryValueEx(hndKey, COMMANDLINE, NULL, &Type, (unsigned char *)WIN32_Service_Command_Line,
                                &Size);
            } else
                WIN32_Service_Command_Line = xstrdup("");

            RegCloseKey(hndKey);
        } else {
            ConfigFile = xstrdup(DefaultConfigFile);
            WIN32_Service_Command_Line = xstrdup("");
        }

        WIN32_build_argv(WIN32_Service_Command_Line);
        *argc = WIN32_argc;
        *argv = WIN32_argv;
        /* Set Service Status to SERVICE_START_PENDING */
        svcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        svcStatus.dwCurrentState = SERVICE_START_PENDING;
        svcStatus.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        svcStatus.dwWin32ExitCode = 0;
        svcStatus.dwServiceSpecificExitCode = 0;
        svcStatus.dwCheckPoint = 0;
        svcStatus.dwWaitHint = 10000;
        SetServiceStatus(svcHandle, &svcStatus);
#ifdef _SQUID_MSWIN_

        _setmaxstdio(Squid_MaxFD);
#endif

    }

#endif /* USE_WIN32_SERVICE */
#ifdef _SQUID_MSWIN_
    if (Win32SockInit() < 0)
        return 1;

#endif

    return 0;
}

#if USE_WIN32_SERVICE
void
WIN32_svcstatusupdate(DWORD svcstate, DWORD WaitHint)
{
    if (WIN32_run_mode == _WIN_SQUID_RUN_MODE_SERVICE) {
        svcStatus.dwCheckPoint++;
        svcStatus.dwWaitHint = WaitHint;
        svcStatus.dwCurrentState = svcstate;
        SetServiceStatus(svcHandle, &svcStatus);
    }
}

VOID WINAPI
WIN32_svcHandler(DWORD Opcode)
{
    DWORD status;

    switch (Opcode) {

    case _WIN_SQUID_SERVICE_CONTROL_STOP:

    case _WIN_SQUID_SERVICE_CONTROL_SHUTDOWN:
        /* Do whatever it takes to stop here. */
        svcStatus.dwWin32ExitCode = 0;
        svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
        svcStatus.dwCheckPoint = 0;
        svcStatus.dwWaitHint = 10000;
        shut_down(SIGTERM);

        if (!SetServiceStatus(svcHandle, &svcStatus)) {
            status = GetLastError();
            debugs(1, 1, "SetServiceStatus error " << status);
        }

        debugs(1, 1, "Leaving Squid service");
        return;

    case _WIN_SQUID_SERVICE_CONTROL_INTERROGATE:
        /* Fall through to send current status. */

        if (!SetServiceStatus(svcHandle, &svcStatus)) {
            status = GetLastError();
            debugs(1, 1, "SetServiceStatus error " << status);
        }

        break;

    case _WIN_SQUID_SERVICE_CONTROL_ROTATE:
        rotate_logs(SIGUSR1);
        break;

    case _WIN_SQUID_SERVICE_CONTROL_RECONFIGURE:
        reconfigure(SIGHUP);
        break;

    case _WIN_SQUID_SERVICE_CONTROL_DEBUG:
        sigusr2_handle(SIGUSR2);
        break;

    case _WIN_SQUID_SERVICE_CONTROL_INTERRUPT:
        /* Do whatever it takes to stop here. */
        svcStatus.dwWin32ExitCode = 0;
        svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
        svcStatus.dwCheckPoint = 0;
        svcStatus.dwWaitHint = 10000;
        shut_down(SIGINT);

        if (!SetServiceStatus(svcHandle, &svcStatus)) {
            status = GetLastError();
            debugs(1, 1, "SetServiceStatus error " << status);
        }

        debugs(1, 1, "Leaving Squid service");
        break;

    default:
        debugs(1, 1, "Unrecognized opcode " << Opcode);
    }

    return;
}

void
WIN32_RemoveService()
{
    SC_HANDLE schService;
    SC_HANDLE schSCManager;

    if (!WIN32_Service_name)
        WIN32_Service_name = xstrdup(_WIN_SQUID_DEFAULT_SERVICE_NAME);

    strcat(REGKEY, WIN32_Service_name);

    keys[4] = WIN32_Service_name;

    schSCManager = OpenSCManager(NULL,	/* machine (NULL == local)    */
                                 NULL,			/* database (NULL == default) */
                                 SC_MANAGER_ALL_ACCESS	/* access required            */
                                );

    if (!schSCManager)
        fprintf(stderr, "OpenSCManager failed\n");
    else {
        schService = OpenService(schSCManager, WIN32_Service_name, SERVICE_ALL_ACCESS);

        if (schService == NULL)
            fprintf(stderr, "OpenService failed\n");

        /* Could not open the service */
        else {
            /* try to stop the service */

            if (ControlService(schService, _WIN_SQUID_SERVICE_CONTROL_STOP,
                               &svcStatus)) {
                sleep(1);

                while (QueryServiceStatus(schService, &svcStatus)) {
                    if (svcStatus.dwCurrentState == SERVICE_STOP_PENDING)
                        sleep(1);
                    else
                        break;
                }
            }

            /* now remove the service */
            if (DeleteService(schService) == 0)
                fprintf(stderr, "DeleteService failed.\n");
            else
                printf("Service %s deleted successfully.\n",
                       WIN32_Service_name);

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }
}

void
WIN32_SetServiceCommandLine()
{
    if (!WIN32_Service_name)
        WIN32_Service_name = xstrdup(_WIN_SQUID_DEFAULT_SERVICE_NAME);

    strcat(REGKEY, WIN32_Service_name);

    keys[4] = WIN32_Service_name;

    /* Now store the Service Command Line in the registry */
    WIN32_StoreKey(COMMANDLINE, REG_SZ, (unsigned char *) WIN32_Command_Line, strlen(WIN32_Command_Line) + 1);
}

void
WIN32_InstallService()
{
    SC_HANDLE schService;
    SC_HANDLE schSCManager;
    char ServicePath[512];
    char szPath[512];
    int lenpath;

    if (!WIN32_Service_name)
        WIN32_Service_name = xstrdup(_WIN_SQUID_DEFAULT_SERVICE_NAME);

    strcat(REGKEY, WIN32_Service_name);

    keys[4] = WIN32_Service_name;

    if ((lenpath = GetModuleFileName(NULL, ServicePath, 512)) == 0) {
        fprintf(stderr, "Can't get executable path\n");
        exit(1);
    }

    snprintf(szPath, sizeof(szPath), "%s %s:%s", ServicePath, _WIN_SQUID_SERVICE_OPTION, WIN32_Service_name);
    schSCManager = OpenSCManager(NULL,	/* machine (NULL == local)    */
                                 NULL,			/* database (NULL == default) */
                                 SC_MANAGER_ALL_ACCESS	/* access required            */
                                );

    if (!schSCManager) {
        fprintf(stderr, "OpenSCManager failed\n");
        exit(1);
    } else {
        schService = CreateService(schSCManager,    /* SCManager database     */
                                   WIN32_Service_name,			    /* name of service        */
                                   WIN32_Service_name,			    /* name to display        */
                                   SERVICE_ALL_ACCESS,			    /* desired access         */
                                   SERVICE_WIN32_OWN_PROCESS,		    /* service type           */
                                   SERVICE_AUTO_START,			    /* start type             */
                                   SERVICE_ERROR_NORMAL,		    /* error control type     */
                                   (const char *) szPath,		    /* service's binary       */
                                   NULL,				    /* no load ordering group */
                                   NULL,				    /* no tag identifier      */
                                   "Tcpip\0AFD\0",			    /* dependencies           */
                                   NULL,				    /* LocalSystem account    */
                                   NULL);				    /* no password            */

        if (schService) {
            if (WIN32_OS_version > _WIN_OS_WINNT) {
                HMODULE ADVAPI32Handle;
                PFChangeServiceConfig2 ChangeServiceConfig2;
                DWORD dwInfoLevel = SERVICE_CONFIG_DESCRIPTION;

                ADVAPI32Handle = GetModuleHandle("advapi32");
                ChangeServiceConfig2 = (PFChangeServiceConfig2) GetProcAddress(ADVAPI32Handle, CHANGESERVICECONFIG2);
                ChangeServiceConfig2(schService, dwInfoLevel, &Squid_ServiceDescription);
                dwInfoLevel = SERVICE_CONFIG_FAILURE_ACTIONS;
                ChangeServiceConfig2(schService, dwInfoLevel, &Squid_ServiceFailureActions);
            }

            CloseServiceHandle(schService);
            /* Now store the config file location in the registry */

            if (!ConfigFile)
                ConfigFile = xstrdup(DefaultConfigFile);

            WIN32_StoreKey(CONFIGFILE, REG_SZ, (unsigned char *) ConfigFile, strlen(ConfigFile) + 1);

            printf("Squid Cache version %s for %s\n", version_string,
                   CONFIG_HOST_TYPE);

            printf("installed successfully as %s Windows System Service.\n",
                   WIN32_Service_name);

            printf
            ("To run, start it from the Services Applet of Control Panel.\n");

            printf("Don't forget to edit squid.conf before starting it.\n\n");
        } else {
            fprintf(stderr, "CreateService failed\n");
            exit(1);
        }

        CloseServiceHandle(schSCManager);
    }
}

void
WIN32_sendSignal(int WIN32_signal)
{
    SERVICE_STATUS ssStatus;
    DWORD fdwAccess, fdwControl;
    SC_HANDLE schService;
    SC_HANDLE schSCManager;

    if (!WIN32_Service_name)
        WIN32_Service_name = xstrdup(_WIN_SQUID_DEFAULT_SERVICE_NAME);

    schSCManager = OpenSCManager(NULL,	/* machine (NULL == local)    */
                                 NULL,			/* database (NULL == default) */
                                 SC_MANAGER_ALL_ACCESS	/* access required            */
                                );

    if (!schSCManager) {
        fprintf(stderr, "OpenSCManager failed\n");
        exit(1);
    }

    /* The required service object access depends on the control. */
    switch (WIN32_signal) {

    case 0:			/* SIGNULL */
        fdwAccess = SERVICE_INTERROGATE;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_INTERROGATE;
        break;

    case SIGUSR1:
        fdwAccess = SERVICE_USER_DEFINED_CONTROL;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_ROTATE;
        break;

    case SIGUSR2:
        fdwAccess = SERVICE_USER_DEFINED_CONTROL;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_DEBUG;
        break;

    case SIGHUP:
        fdwAccess = SERVICE_USER_DEFINED_CONTROL;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_RECONFIGURE;
        break;

    case SIGTERM:
        fdwAccess = SERVICE_STOP;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_STOP;
        break;

    case SIGINT:

    case SIGKILL:
        fdwAccess = SERVICE_USER_DEFINED_CONTROL;
        fdwControl = _WIN_SQUID_SERVICE_CONTROL_INTERRUPT;
        break;

    default:
        exit(1);
    }

    /* Open a handle to the service. */
    schService = OpenService(schSCManager,	/* SCManager database */
                             WIN32_Service_name,	/* name of service    */
                             fdwAccess);		/* specify access     */

    if (schService == NULL) {
        fprintf(stderr, "%s: ERROR: Could not open Service %s\n", appname,
                WIN32_Service_name);
        exit(1);
    } else {
        /* Send a control value to the service. */

        if (!ControlService(schService,	/* handle of service      */
                            fdwControl,	/* control value to send  */
                            &ssStatus)) {	/* address of status info */
            fprintf(stderr, "%s: ERROR: Could not Control Service %s\n",
                    appname, WIN32_Service_name);
            exit(1);
        } else {
            /* Print the service status. */
            printf("\nStatus of %s Service:\n", WIN32_Service_name);
            printf("  Service Type: 0x%lx\n", ssStatus.dwServiceType);
            printf("  Current State: 0x%lx\n", ssStatus.dwCurrentState);
            printf("  Controls Accepted: 0x%lx\n", ssStatus.dwControlsAccepted);
            printf("  Exit Code: %ld\n", ssStatus.dwWin32ExitCode);
            printf("  Service Specific Exit Code: %ld\n",
                   ssStatus.dwServiceSpecificExitCode);
            printf("  Check Point: %ld\n", ssStatus.dwCheckPoint);
            printf("  Wait Hint: %ld\n", ssStatus.dwWaitHint);
        }

        CloseServiceHandle(schService);
    }

    CloseServiceHandle(schSCManager);
}

int main(int argc, char **argv)
{
    SERVICE_TABLE_ENTRY DispatchTable[] = {
                                              {NULL, SquidWinSvcMain},
                                              {NULL, NULL}
                                          };
    char *c;
    char stderr_path[256];

    if ((argc == 2) && strstr(argv[1], _WIN_SQUID_SERVICE_OPTION)) {
        strcpy(stderr_path, argv[0]);
        strcat(stderr_path,".log");
        freopen(stderr_path, "w", stderr);
        setmode(fileno(stderr), O_TEXT);
        WIN32_run_mode = _WIN_SQUID_RUN_MODE_SERVICE;

        if (!(c=strchr(argv[1],':'))) {
            fprintf(stderr, "Bad Service Parameter: %s\n", argv[1]);
            return 1;
        }

        WIN32_Service_name = xstrdup(c+1);
        DispatchTable[0].lpServiceName=WIN32_Service_name;
        strcat(REGKEY, WIN32_Service_name);
        keys[4] = WIN32_Service_name;

        if (!StartServiceCtrlDispatcher(DispatchTable)) {
            fprintf(stderr, "StartServiceCtrlDispatcher error = %ld\n",
                    GetLastError());
            return 1;
        }
    } else {
        WIN32_run_mode = _WIN_SQUID_RUN_MODE_INTERACTIVE;
#ifdef _SQUID_MSWIN_

        opt_no_daemon = 1;

#endif

        return SquidMain(argc, argv);
    }

    return 0;
}

#endif /* USE_WIN32_SERVICE */

#if defined(_SQUID_MSWIN_)
static int Win32SockInit(void)
{
    int iVersionRequested;
    WSADATA wsaData;
    int err, opt;
    int optlen = sizeof(opt);

    if (s_iInitCount > 0) {
        s_iInitCount++;
        return (0);
    } else if (s_iInitCount < 0)
        return (s_iInitCount);

    /* s_iInitCount == 0. Do the initailization */
    iVersionRequested = MAKEWORD(2, 0);

    err = WSAStartup((WORD) iVersionRequested, &wsaData);

    if (err) {
        s_iInitCount = -1;
        return (s_iInitCount);
    }

    if (LOBYTE(wsaData.wVersion) != 2 ||
            HIBYTE(wsaData.wVersion) != 0) {
        s_iInitCount = -2;
        WSACleanup();
        return (s_iInitCount);
    }

    if (WIN32_OS_version !=_WIN_OS_WINNT) {
        if (::getsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&opt, &optlen)) {
            s_iInitCount = -3;
            WSACleanup();
            return (s_iInitCount);
        } else {
            opt = opt | SO_SYNCHRONOUS_NONALERT;

            if (::setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *) &opt, optlen)) {
                s_iInitCount = -3;
                WSACleanup();
                return (s_iInitCount);
            }
        }
    }

    WIN32_Socks_initialized = 1;
    s_iInitCount++;
    return (s_iInitCount);
}

static void Win32SockCleanup(void)
{
    if (--s_iInitCount == 0)
        WSACleanup();

    return;
}

void Squid_Win32InvalidParameterHandler(const wchar_t* expression, const wchar_t* function, const wchar_t* file, unsigned int line, uintptr_t pReserved)
{
    return;
}

#endif /* SQUID_MSWIN_ */
