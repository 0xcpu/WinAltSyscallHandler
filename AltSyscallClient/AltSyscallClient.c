#include <Windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <AltSyscall.h>

#define ALTSYSCALL_SERVICE_NAMEW        L"AltSyscallSvc"
#define ALTSYSCALL_DEVICE_NAMEW         L"\\\\.\\AltSyscall"
#define ALTSYSCALL_SERVICE_INSTALL      0
#define ALTSYSCALL_SERVICE_UNINSTALL    1
#define ALTSYSCALL_MONITOR_IOCTL        IOCTL_ALT_SYSCALL_DRIVER


_Success_(return == TRUE)
BOOLEAN
InstallDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName,
    _In_	LPCTSTR		DriverPath
)
{
    SC_HANDLE   schService;
    DWORD       errCode;

    schService = CreateService(hSCManager,
                               ServiceName,
                               ServiceName,
                               SERVICE_ALL_ACCESS,
                               SERVICE_KERNEL_DRIVER,
                               SERVICE_DEMAND_START,
                               SERVICE_ERROR_NORMAL,
                               DriverPath,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
    if (NULL == schService) {
        errCode = GetLastError();

        if (ERROR_SERVICE_EXISTS == errCode) {
            fprintf(stderr, "[AltSyscallClient] Service already exists\n");

            return TRUE;
        } else {
            fprintf(stderr, "[AltSyscallClient] Failed creating service: %#x\n", errCode);

            return FALSE;
        }
    } else {
        CloseServiceHandle(schService);

        fprintf(stdout, "[AltSyscallClient] Service %S was successfully created\n", ServiceName);

        return TRUE;
    }
}

_Success_(return == TRUE)
BOOLEAN
UninstallDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE   schService;
    BOOLEAN     bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, "[AltSyscallClient] Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (DeleteService(schService)) {
        bRetStatus = TRUE;

        fprintf(stdout, "[AltSyscallClient] Service %S was successfully deleted\n", ServiceName);
    } else {
        fprintf(stderr, "[AltSyscallClient] Failed deleting the service: %#X\n", GetLastError());
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
StartDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE   schService;
    DWORD       errCode;
    BOOLEAN     bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, "[AltSyscallClient] Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (!StartService(schService,
                      0,
                      NULL)) {
        errCode = GetLastError();

        if (ERROR_SERVICE_ALREADY_RUNNING == errCode) {
            bRetStatus = TRUE;

            fprintf(stdout, "[AltSyscallClient] Service %S already running\n", ServiceName);
        } else {
            fprintf(stderr, "[AltSyscallClient] Failed starting the service: %#X\n", errCode);
        }
    } else {
        bRetStatus = TRUE;

        fprintf(stdout, "[AltSyscallClient] Service %S was successfully started\n", ServiceName);
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
StopDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE       schService;
    SERVICE_STATUS  serviceStatus;
    BOOLEAN         bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, "[AltSyscallClient] Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (ControlService(schService,
                       SERVICE_CONTROL_STOP,
                       &serviceStatus)) {
        bRetStatus = TRUE;

        fprintf(stdout, "[AltSyscallClient] Service %S was successfully stopped\n", ServiceName);
    } else {
        fprintf(stderr, "[AltSyscallClient] Failed stopping the service: %#X\n", GetLastError());
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
ManageDriver(
    _In_    LPCTSTR		DriverPath,
    _In_    LPCTSTR		ServiceName,
    _In_    SIZE_T		Action
)
{
    SC_HANDLE	schSCManager;
    BOOLEAN		bRetVal = TRUE;

    if (NULL == DriverPath || NULL == ServiceName) {
        fprintf(stderr, "[AltSyscallClient] Invalid driver name or service name\n");

        return FALSE;
    }

    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schSCManager) {
        fprintf(stderr, "[AltSyscallClient] Failed opening a connection to SCM: %#X\n", GetLastError());

        return FALSE;
    }

    switch (Action) {
    case ALTSYSCALL_SERVICE_INSTALL:
        if (InstallDriver(schSCManager, ServiceName, DriverPath)) {
            bRetVal = StartDriver(schSCManager, ServiceName);
        } else {
            bRetVal = FALSE;
        }

        break;
    case ALTSYSCALL_SERVICE_UNINSTALL:
        if (StopDriver(schSCManager, ServiceName)) {
            bRetVal = UninstallDriver(schSCManager, ServiceName);
        } else {
            bRetVal = FALSE;
        }

        break;
    default:
        fprintf(stderr, "[AltSyscallClient] Unknown action: %zu\n", Action);

        bRetVal = FALSE;

        break;
    }

    if (CloseServiceHandle(schSCManager) == 0) {
        fprintf(stderr, "[AltSyscallClient] Failed closing SCM: %#X\n", GetLastError());
    }

    return bRetVal;
}

int __cdecl main(int argc, char *argv[])
{
    UNREFERENCED_PARAMETER(argv);

    DWORD       retCode = EXIT_SUCCESS;
    DWORD       dwBufferLength = 0;
    DWORD       dwPid = 0;
    DWORD       dwBytesReturned;
    errno_t     intErrNo;
    LPWSTR      lpBuffer = NULL;
    LPCWSTR     lpDriverName = DRIVER_NAME;
    HANDLE      hDevice;
    BOOL        bRet;
    HANDLE      pid;

    if (argc > 1) {
        if (_strnicmp(argv[1], "load", strlen("load")) == 0) {
            dwBufferLength = GetCurrentDirectory(dwBufferLength, lpBuffer);
            if (!dwBufferLength) {
                retCode = GetLastError();
                fwprintf(stderr, L"Failed to query current directory length: %08X\n", retCode);

                return retCode;
            } else {
                lpBuffer = calloc(dwBufferLength + wcslen(lpDriverName) + 2, sizeof(WCHAR)); // + 2: 1 for \ and 1 for NULL
                if (NULL == lpBuffer) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed allocating a buffer for current directory: %08X\n", retCode);

                    return retCode;
                }

                if (!GetCurrentDirectory(dwBufferLength, lpBuffer)) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed to query current directory length: %08X\n", retCode);

                    free(lpBuffer);
                    lpBuffer = NULL;

                    return retCode;
                }

                wcsncat_s(lpBuffer, dwBufferLength + wcslen(lpDriverName) + 1, L"\\", wcslen(L"\\"));
                wcsncat_s(lpBuffer, dwBufferLength + wcslen(lpDriverName) + 1, lpDriverName, wcslen(lpDriverName));

                fwprintf(stdout, L"Absolute of the driver to load: %lS\n", lpBuffer);
            }

            ManageDriver(lpBuffer, ALTSYSCALL_SERVICE_NAMEW, ALTSYSCALL_SERVICE_INSTALL);

            free(lpBuffer);
            lpBuffer = NULL;
        } else if (_strnicmp(argv[1], "unload", strlen("unload")) == 0) {
            ManageDriver(L"", ALTSYSCALL_SERVICE_NAMEW, ALTSYSCALL_SERVICE_UNINSTALL);
        } else {
            dwPid = strtoul(argv[1], NULL, 10);
            if (0 == dwPid) {
                retCode = GetLastError();
                fwprintf(stderr, L"Failed to convert %hs to a number: %08X\n", argv[1], retCode);

                return retCode;
            } else if (ULONG_MAX == dwPid) {
                retCode = GetLastError();
                fwprintf(stderr, L"Failed to convert %hs to a number, overflow\n", argv[1]);

                return retCode;
            } else if (!_get_errno(&intErrNo) && (intErrNo == ERANGE)) {
                retCode = GetLastError();
                fwprintf(stderr, L"Failed to convert %hs to a number, errno out of range: %08X\n", argv[1], retCode);

                return retCode;
            } else {
                fwprintf(stdout, L"Monitor PID: %lu\n", dwPid);
                
               hDevice = CreateFile(ALTSYSCALL_DEVICE_NAMEW,
								     GENERIC_READ | GENERIC_WRITE,
                                     0,
                                     NULL,
                                     CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     NULL);

                if (hDevice == INVALID_HANDLE_VALUE) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed to open device : %08X\n", retCode);

                    return retCode;
                }

                pid = UlongToHandle(dwPid);
                bRet = DeviceIoControl(hDevice,
                                       ALTSYSCALL_MONITOR_IOCTL,
                                       &pid,
                                       sizeof(HANDLE),
                                       NULL,
                                       0,
                                       &dwBytesReturned,
                                       NULL
                );

                if (!bRet) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed to send PID for monitoring: %08X\n", retCode);

                    return retCode;
                }
            }
        }
    } else {
        fwprintf(stdout, L"Usage: %hs <load | unload | pid>\n", argv[0]);
    }

    return retCode;
}