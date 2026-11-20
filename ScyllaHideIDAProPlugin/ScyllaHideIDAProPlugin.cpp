#ifndef USE_STANDARD_FILE_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#endif
#ifndef USE_DANGEROUS_FUNCTIONS
#define USE_DANGEROUS_FUNCTIONS
#endif
#pragma warning(disable : 4996 4512 4127 4201)

#include <Windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#include <Scylla/Logger.h>
#include <Scylla/Settings.h>
#include <Scylla/Version.h>
#include <Scylla/Util.h>
#include <Scylla/OsInfo.h>

#include "..\PluginGeneric\Injector.h"
#include "..\PluginGeneric\OptionsDialog.h"
#include "IdaServerClient.h"
#include "resource.h"

typedef void(__cdecl * t_AttachProcess)(DWORD dwPID);
extern t_AttachProcess _AttachProcess;

#ifdef _WIN64
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx64.dll";
#else
const WCHAR g_scyllaHideDllFilename[] = L"HookLibraryx86.dll";
#endif
const WCHAR g_scyllaHidex64ServerFilename[] = L"ScyllaHideIDAServerx64.exe";
const WCHAR g_scyllaHidex86ServerFilename[] = L"ScyllaHideIDAServerx86.exe";

scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideDllPath;
std::wstring g_scyllaHideIniPath;
std::wstring g_scyllaHidex64ServerPath;
std::wstring g_scyllaHidex86ServerPath;

HOOK_DLL_DATA g_hdd;

// globals
HINSTANCE hinst = nullptr;
DWORD ProcessId = 0;
bool bHooked = false;
bool g_usingServer = false;
HMODULE hNtdllModule = nullptr;
PROCESS_INFORMATION ServerProcessInfo = { 0 };
STARTUPINFOW ServerStartupInfo = { 0 };
std::wstring g_runningServerPath;
bool isAttach = false;

static void LogCallback(const char *message)
{
    msg("[%s] %s\n", SCYLLA_HIDE_NAME_A, message);
}

static bool IsTargetProcessWow64(DWORD pid)
{
    if (!scl::IsWindows64())
        return false;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
        return false;

    bool isWow64 = scl::IsWow64Process(hProcess);
    CloseHandle(hProcess);
    return isWow64;
}

static bool EnsureServerRunning(const std::wstring &serverPath)
{
    if (!scl::FileExistsW(serverPath.c_str()))
    {
        g_log.LogError(L"Cannot find server executable %s", serverPath.c_str());
        return false;
    }

    DWORD dwRunningStatus = 0;
    if (ServerProcessInfo.hProcess)
    {
        GetExitCodeProcess(ServerProcessInfo.hProcess, &dwRunningStatus);
        if (dwRunningStatus == STILL_ACTIVE && g_runningServerPath == serverPath)
        {
            return true;
        }
        if (dwRunningStatus == STILL_ACTIVE && g_runningServerPath != serverPath)
        {
            TerminateProcess(ServerProcessInfo.hProcess, 0);
            WaitForSingleObject(ServerProcessInfo.hProcess, 1000);
        }
        CloseHandle(ServerProcessInfo.hProcess);
        CloseHandle(ServerProcessInfo.hThread);
        ZeroMemory(&ServerProcessInfo, sizeof(ServerProcessInfo));
    }

    ZeroMemory(&ServerStartupInfo, sizeof(ServerStartupInfo));
    ServerStartupInfo.cb = sizeof(ServerStartupInfo);

    std::wstring cmdline = L"\"" + serverPath + L"\" " + g_settings.opts().idaServerPort;
    std::vector<WCHAR> cmdBuf(cmdline.begin(), cmdline.end());
    cmdBuf.push_back(L'\0');

    if (!CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &ServerStartupInfo, &ServerProcessInfo))
    {
        g_log.LogError(L"Cannot start server %s, error %lu", serverPath.c_str(), GetLastError());
        return false;
    }

    g_runningServerPath = serverPath;
    g_log.LogInfo(L"Started IDA Server successfully: %s", serverPath.c_str());
    return true;
}

static bool ConnectToServerWithRetry(const char *host, const char *port, int maxAttempts = 10)
{
    for (int i = 0; i < maxAttempts; ++i)
    {
        if (ConnectToServer(host, port))
            return true;
        Sleep(100);
    }
    return false;
}

void IdaApplySettings(unsigned long pid)
{
    if (!pid)
        return;

    if (g_usingServer)
    {
        if (!SendEventToServer(dbg_process_start, pid))
        {
            g_log.LogError(L"SendEventToServer failed when applying settings");
        }
    }
    else
    {
        ReadNtApiInformation(&g_hdd);
        startInjection(pid, &g_hdd, g_scyllaHideDllPath.c_str(), true);
    }
}

void IdaInjectDll(unsigned long pid, const wchar_t *dllPath)
{
    if (!pid || !dllPath)
        return;

    if (g_usingServer)
    {
        SendInjectToServer(pid);
    }
    else
    {
        injectDll(pid, dllPath);
    }
}

static void AttachProcess(DWORD dwPID)
{
    int res = attach_process((pid_t)dwPID);

    switch (res)
    {
    case -1:
        MessageBoxA(GetActiveWindow(),
            "Can't attach to that process!",
            "ScyllaHide Plugin", MB_OK | MB_ICONERROR);
        break;
    case -2:
        MessageBoxA(GetActiveWindow(),
            "Can't find that PID!",
            "ScyllaHide Plugin", MB_OK | MB_ICONERROR);
        break;
    default:
        break;
    }
}

static bool SetDebugPrivileges()
{
    TOKEN_PRIVILEGES Debug_Privileges;
    bool retVal = false;

    if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        HANDLE hToken = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
        {
            Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            Debug_Privileges.PrivilegeCount = 1;

            retVal = AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, nullptr, nullptr) != FALSE;

            CloseHandle(hToken);
        }
    }

    return retVal;
}

struct scyllahide_plugmod_t : public plugmod_t, public event_listener_t
{
    bool hooked = false;

    scyllahide_plugmod_t()
    {
        hooked = hook_event_listener(HT_DBG, this);
    }

    virtual ~scyllahide_plugmod_t()
    {
        if (hooked)
        {
            unhook_event_listener(HT_DBG, this);
            hooked = false;
        }
        CloseServerSocket();
    }

    virtual bool idaapi run(size_t /*arg*/) override
    {
        DialogBoxW(hinst, MAKEINTRESOURCEW(IDD_OPTIONS), GetActiveWindow(), &OptionsDlgProc);
        return true;
    }

    virtual ssize_t idaapi on_event(ssize_t notif_code, va_list va) override
    {
        switch (notif_code)
        {
        case dbg_process_attach:
        {
            isAttach = true;
            break; // attaching not supported
        }

        case dbg_process_start:
        {
            isAttach = false;

            const debug_event_t *dbgEvent = va_arg(va, const debug_event_t *);
            if (!dbgEvent)
                break;

            ProcessId = (DWORD)dbgEvent->pid;
            bHooked = false;
            g_usingServer = false;
            ZeroMemory(&g_hdd, sizeof(HOOK_DLL_DATA));

            if (dbg != nullptr)
            {
                char port[16] = { 0 };
                wcstombs(port, g_settings.opts().idaServerPort.c_str(), _countof(port) - 1);

                if (dbg->is_remote())
                {
                    g_usingServer = true;

                    qstring hoststring;
                    char host[MAX_PATH] = { 0 };
                    get_process_options(nullptr, nullptr, nullptr, nullptr, &hoststring, nullptr, nullptr);
                    GetHost((char *)hoststring.c_str(), host);
                    if (host[0] == '\0')
                        strcpy_s(host, "127.0.0.1");

                    bool startedNow = false;
                    if (g_settings.opts().idaAutoStartServer)
                    {
                        const std::wstring &serverPath = inf_is_64bit()
                            ? g_scyllaHidex64ServerPath
                            : g_scyllaHidex86ServerPath;
                        startedNow = EnsureServerRunning(serverPath);
                    }

                    bool connected = startedNow
                        ? ConnectToServerWithRetry(host, port)
                        : ConnectToServer(host, port);

                    if (connected)
                    {
                        if (!SendEventToServer((unsigned long)notif_code, ProcessId))
                        {
                            g_log.LogError(L"SendEventToServer failed");
                        }
                        else
                        {
                            bHooked = true;
                        }
                    }
                    else
                    {
                        g_log.LogError(L"Cannot connect to host %S:%S", host, port);
                    }
                }
                else
                {
#ifdef _WIN64
                    if (IsTargetProcessWow64(ProcessId))
                    {
                        // Local 32-bit (WOW64) target from 64-bit IDA: delegate to ScyllaHideIDAServerx86.exe
                        g_usingServer = true;
                        bool startedNow = EnsureServerRunning(g_scyllaHidex86ServerPath);
                        bool connected = startedNow
                            ? ConnectToServerWithRetry("127.0.0.1", port)
                            : ConnectToServer("127.0.0.1", port);

                        if (connected)
                        {
                            if (!SendEventToServer((unsigned long)notif_code, ProcessId))
                            {
                                g_log.LogError(L"SendEventToServer failed for WOW64 target PID %lu", ProcessId);
                            }
                            else
                            {
                                bHooked = true;
                            }
                        }
                        else
                        {
                            g_log.LogError(L"Cannot connect to local x86 IDA server on port %S for 32-bit target", port);
                        }
                    }
                    else
                    {
                        // Local 64-bit target from 64-bit IDA: inject HookLibraryx64.dll directly
                        ReadNtApiInformation(&g_hdd);
                        bHooked = true;
                        startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
                    }
#else
                    if (!scl::IsWindows64() && !bHooked)
                    {
                        ReadNtApiInformation(&g_hdd);
                        bHooked = true;
                        startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), true);
                    }
#endif
                }
            }
            break;
        }

        case dbg_process_exit:
        {
            if (!isAttach && g_usingServer)
            {
                if (!SendEventToServer((unsigned long)notif_code, ProcessId))
                {
                    g_log.LogError(L"SendEventToServer failed");
                }
                CloseServerSocket();
            }
            ProcessId = 0;
            bHooked = false;
            g_usingServer = false;
            break;
        }

        case dbg_library_load:
        {
            if (!isAttach && g_usingServer)
            {
                if (!SendEventToServer((unsigned long)notif_code, ProcessId))
                {
                    g_log.LogError(L"SendEventToServer failed");
                }
            }
            else if (!isAttach && bHooked)
            {
                startInjection(ProcessId, &g_hdd, g_scyllaHideDllPath.c_str(), false);
            }
            break;
        }

        case dbg_bpt:
        {
            (void)va_arg(va, thid_t);
            (void)va_arg(va, ea_t);
            (void)va_arg(va, int *);
            break;
        }

        case dbg_exception:
        {
            (void)va_arg(va, const debug_event_t *);
            break;
        }

        default:
            break;
        }

        return 0;
    }
};

static plugmod_t *idaapi IDAP_init(void)
{
    // Ensure target is PE executable
    if (inf_get_filetype() != f_PE)
        return PLUGIN_SKIP;

    scyllahide_plugmod_t *plugmod = new scyllahide_plugmod_t();
    if (!plugmod->hooked)
    {
        g_log.LogError(L"Error hooking HT_DBG event listener");
        delete plugmod;
        return PLUGIN_SKIP;
    }

    msg("##################################################\n");
    msg("# " SCYLLA_HIDE_NAME_A " v" SCYLLA_HIDE_VERSION_STRING_A " (IDA SDK %d) Copyright 2014-" COMPILE_YEAR_A " Aguila / cypher #\n", IDA_SDK_VERSION);
    msg("##################################################\n");

    bHooked = false;
    g_usingServer = false;
    ProcessId = 0;

    return plugmod;
}

static const char IDAP_comment[] = SCYLLA_HIDE_NAME_A " usermode Anti-Anti-Debug Plugin";
static const char IDAP_help[] = SCYLLA_HIDE_NAME_A;
static const char IDAP_name[] = SCYLLA_HIDE_NAME_A;
static const char IDAP_hotkey[] = "Alt-X";

idaman ida_module_data plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI,
    IDAP_init,
    nullptr,
    nullptr,
    IDAP_comment,
    IDAP_help,
    IDAP_name,
    IDAP_hotkey
};

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID /*lpReserved*/)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        hinst = hInstDll;
        _AttachProcess = AttachProcess;
        hNtdllModule = GetModuleHandleW(L"ntdll.dll");

        auto wstrPath = scl::GetModuleFileNameW(hInstDll);
        wstrPath.resize(wstrPath.find_last_of(L'\\') + 1);

        g_scyllaHideDllPath = wstrPath + g_scyllaHideDllFilename;
        g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;
        g_scyllaHidex64ServerPath = wstrPath + g_scyllaHidex64ServerFilename;
        g_scyllaHidex86ServerPath = wstrPath + g_scyllaHidex86ServerFilename;

        auto log_file = wstrPath + scl::Logger::kFileName;
        g_log.SetLogFile(log_file.c_str());
        g_log.SetLogCb(scl::Logger::Info, LogCallback);
        g_log.SetLogCb(scl::Logger::Error, LogCallback);

        g_settings.Load(g_scyllaHideIniPath.c_str());

        if (!SetDebugPrivileges())
        {
            g_log.LogInfo(L"Failed to set debug privileges");
        }

        if (!StartWinsock())
        {
            MessageBoxW(nullptr, L"Failed to start Winsock!", L"Error", MB_ICONERROR);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        if (ServerProcessInfo.hProcess)
        {
            CloseHandle(ServerProcessInfo.hProcess);
            CloseHandle(ServerProcessInfo.hThread);
            ZeroMemory(&ServerProcessInfo, sizeof(ServerProcessInfo));
        }
    }

    return TRUE;
}
