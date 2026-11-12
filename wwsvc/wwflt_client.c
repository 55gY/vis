/* wwflt_client.c -- user-mode client for the WWFilter driver. */
#include "wwflt_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WWFLT_SVC_NAME "WWFilter"

DWORD wwflt_start_driver(void)
{
    SC_HANDLE scm = NULL, svc = NULL;
    DWORD err = 0;
    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    int i;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    svc = OpenServiceA(scm, WWFLT_SVC_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { err = GetLastError(); CloseServiceHandle(scm); return err; }
    /* Already running? */
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
    /* Wait (up to ~10 s) for it to reach RUNNING. */
    for (i = 0; i < 100; i++) {
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed) &&
            ssp.dwCurrentState == SERVICE_RUNNING) break;
        Sleep(100);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

DWORD wwflt_stop_driver(void)
{
    SC_HANDLE scm = NULL, svc = NULL;
    DWORD err = 0;
    SERVICE_STATUS ss;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return GetLastError();
    svc = OpenServiceA(scm, WWFLT_SVC_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
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

HANDLE wwflt_open(void)
{
    return CreateFileA(WWFLT_WIN32_DEVICE, GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

DWORD wwflt_set_policy(HANDLE h, const WWFLT_POLICY *pol)
{
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_WWFLT_SET_POLICY, (LPVOID)pol, (DWORD)sizeof(WWFLT_POLICY),
                         NULL, 0, &ret, NULL))
        return GetLastError();
    return 0;
}

DWORD wwflt_get_status(HANDLE h, WWFLT_STATUS *st)
{
    DWORD ret = 0;
    memset(st, 0, sizeof(*st));
    if (!DeviceIoControl(h, IOCTL_WWFLT_GET_STATUS, NULL, 0, st, (DWORD)sizeof(*st), &ret, NULL))
        return GetLastError();
    return 0;
}

DWORD wwflt_get_events(HANDLE h, ULONG want, WWFLT_EVENT *out, ULONG *count_out, ULONG *dropped_out)
{
    /* Output buffer: WWFLT_EVENT_COUNT header + up to `want` events. */
    DWORD out_size = (DWORD)(sizeof(WWFLT_EVENT_COUNT) + (size_t)want * sizeof(WWFLT_EVENT));
    BYTE *buf = (BYTE *)malloc(out_size);
    DWORD ret = 0;
    DWORD err = 0;
    if (!buf) return ERROR_NOT_ENOUGH_MEMORY;
    if (!DeviceIoControl(h, IOCTL_WWFLT_GET_EVENTS, &want, sizeof(want), buf, out_size, &ret, NULL)) {
        err = GetLastError();
        free(buf);
        return err;
    }
    {
        WWFLT_EVENT_COUNT *hdr = (WWFLT_EVENT_COUNT *)buf;
        ULONG n = hdr->count;
        if (n > want) n = want;
        if (ret < sizeof(WWFLT_EVENT_COUNT) + n * sizeof(WWFLT_EVENT)) {
            n = (ret > sizeof(WWFLT_EVENT_COUNT)) ? (ret - sizeof(WWFLT_EVENT_COUNT)) / sizeof(WWFLT_EVENT) : 0;
        }
        memcpy(out, buf + sizeof(WWFLT_EVENT_COUNT), n * sizeof(WWFLT_EVENT));
        if (count_out) *count_out = n;
        if (dropped_out) *dropped_out = hdr->dropped;
    }
    free(buf);
    return 0;
}

DWORD wwflt_set_log_level(HANDLE h, ULONG level)
{
    DWORD ret = 0;
    if (!DeviceIoControl(h, IOCTL_WWFLT_SET_LOG_LEVEL, &level, sizeof(level), NULL, 0, &ret, NULL))
        return GetLastError();
    return 0;
}

DWORD wwflt_set_enabled(HANDLE h, ULONG enabled)
{
    WWFLT_CONFIG cfg;
    DWORD ret = 0;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = enabled;
    if (!DeviceIoControl(h, IOCTL_WWFLT_SET_CONFIG, &cfg, sizeof(cfg), NULL, 0, &ret, NULL))
        return GetLastError();
    return 0;
}

static const char *wwflt_event_name(ULONG type)
{
    switch (type) {
    case WWFLT_EVENT_CREATE: return "create";
    case WWFLT_EVENT_READ: return "read";
    case WWFLT_EVENT_WRITE: return "write";
    case WWFLT_EVENT_ENCRYPT: return "encrypt";
    case WWFLT_EVENT_DECRYPT: return "decrypt";
    case WWFLT_EVENT_ERROR: return "error";
    case WWFLT_EVENT_POLICY: return "policy";
    default: return "unknown";
    }
}

int wwflt_log_events_to_file(const char *log_path, const WWFLT_EVENT *events, ULONG count)
{
    FILE *f = fopen(log_path, "a");
    ULONG i;
    int written = 0;
    if (!f) return 0;
    for (i = 0; i < count; i++) {
        const WWFLT_EVENT *e = &events[i];
        /* Timestamp: 100ns ticks since 1601 -> convert to seconds for readability. */
        ULONGLONG sec = e->timestamp_100ns / 10000000ULL;
        char proc[128] = { 0 }, path[512] = { 0 };
        size_t j;
        for (j = 0; j < sizeof(proc) - 1 && e->process[j]; j++) proc[j] = (char)e->process[j];
        for (j = 0; j < sizeof(path) - 1 && e->path[j]; j++) path[j] = (char)e->path[j];
        fprintf(f, "[flt %llu] %-8s pid=%lu proc=%s off=%llu len=%lu status=0x%08lx path=%s\n",
                sec, wwflt_event_name(e->type), e->pid, proc,
                e->offset, e->length, (unsigned long)e->status, path);
        written++;
    }
    fclose(f);
    return written;
}
