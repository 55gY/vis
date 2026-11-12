/* wwinj_client.c -- user-mode client for the WWInject driver. */
#include "wwinj_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WWINJ_SVC_NAME "WWInject"

DWORD wwinj_start_driver(void)
{
    SC_HANDLE scm = NULL, svc = NULL;
    DWORD err = 0;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    int i;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    svc = OpenServiceA(scm, WWINJ_SVC_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { err = GetLastError(); CloseServiceHandle(scm); return err; }
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        if (ssp.dwCurrentState == SERVICE_RUNNING) { CloseServiceHandle(svc); CloseServiceHandle(scm); return 0; }
    }
    if (!StartServiceA(svc, 0, NULL)) {
        err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(svc); CloseServiceHandle(scm);
            return err;
        }
        err = 0;
    }
    for (i = 0; i < 100; i++) {
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed) &&
            ssp.dwCurrentState == SERVICE_RUNNING) break;
        Sleep(100);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

DWORD wwinj_stop_driver(void)
{
    SC_HANDLE scm = NULL, svc = NULL;
    DWORD err = 0;
    SERVICE_STATUS ss;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    svc = OpenServiceA(scm, WWINJ_SVC_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { err = GetLastError(); CloseServiceHandle(scm); return err; }
    if (!ControlService(svc, SERVICE_CONTROL_STOP, &ss)) {
        err = GetLastError();
        if (err != ERROR_SERVICE_NOT_ACTIVE) {
            CloseServiceHandle(svc); CloseServiceHandle(scm);
            return err;
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

HANDLE wwinj_open(void)
{
    return CreateFileA(WWINJ_WIN32_DEVICE, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

DWORD wwinj_set_dll_path(HANDLE h, const WCHAR *dll_path, ULONGLONG load_library_w)
{
    WWINJ_DLL_PATH p;
    DWORD ret = 0;
    memset(&p, 0, sizeof(p));
    wcsncpy(p.path, dll_path, WWINJ_MAX_DLL_PATH - 1);
    p.load_library_w = load_library_w;
    if (!DeviceIoControl(h, IOCTL_WWINJ_SET_DLL_PATH, &p, (DWORD)sizeof(p),
                         NULL, 0, &ret, NULL))
        return GetLastError();
    return 0;
}

DWORD wwinj_set_targets(HANDLE h, const WWINJ_TARGETS *targets)
{
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_WWINJ_SET_TARGETS, (LPVOID)targets, (DWORD)sizeof(*targets),
                         NULL, 0, &ret, NULL))
        return GetLastError();
    return 0;
}

DWORD wwinj_inject_pid(HANDLE h, ULONG pid, LONG *status_out)
{
    WWINJ_INJECT req;
    DWORD ret = 0;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    if (!DeviceIoControl(h, IOCTL_WWINJ_INJECT_PID, &req, (DWORD)sizeof(req),
                         &req, (DWORD)sizeof(req), &ret, NULL))
        return GetLastError();
    if (status_out) *status_out = req.status;
    return 0;
}

DWORD wwinj_get_status(HANDLE h, WWINJ_STATUS *st)
{
    DWORD ret = 0;
    memset(st, 0, sizeof(*st));
    if (!DeviceIoControl(h, IOCTL_WWINJ_GET_STATUS, NULL, 0, st, (DWORD)sizeof(*st), &ret, NULL))
        return GetLastError();
    return 0;
}
