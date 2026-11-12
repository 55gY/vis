/* wwsvc.c -- WaterWall new client core service (Phase 1.2, MVP).
 *
 * Replaces the vendor service layer (wwall.exe / wwinnt.exe / wwsetkrn.exe)
 * with new code. The vendor drivers (wwkernel.sys, wwhost.sys) and the
 * vendor engine DLLs (wwconver.dll / wwkrn.dll) are used UNCHANGED:
 * transparent encryption is still 100% vendor code.
 *
 * What this service does (all verified live in wwprobe1/2/2b/3):
 *  - starts the wwkernel + WWHost driver services via SCM if stopped
 *  - reads the injection config (registry DLL %03d entries) and verifies it
 *  - opens \\.\Global\WWHost, command 1 probe, command 3 self-register
 *    (command 5 deregister on clean shutdown)
 *  - reads <installdir>\wwkrn.xcf (raw DEFLATE + GBK) for the USB policy
 *    (Kernel/usb + Kernel/usb_white_list), applies 0x26 (whitelist, only
 *    when present) then 0x18 (USBPVG verb), verifies with 0x1e before/after
 *  - runs one 0x22e014 waiter thread per injection entry, logging every
 *    newly injected process (new pid, parent pid, session, flags, next key)
 *  - single instance (named mutex), logging to console + wwsvc.log
 *  - NO license code at all: no wwntsys.dll, no license TCP, no License /
 *    LicenseTime reads, no install-count tracking.
 *
 * Run modes:
 *  - console:  wwsvc.exe console        (or just double-click / run it:
 *    if StartServiceCtrlDispatcher fails because SCM did not start us,
 *    we fall back to console mode)
 *  - service:  install once with
 *      sc create WWNewSvc binPath= "D:\path\wwsvc.exe" start= auto
 *    then `sc start WWNewSvc`.
 *
 * Test (user's Win10 PC, old client installed):
 *  - run:  wwsvc.exe console
 *  - wait ~10 s, then start notepad (a new process gets injected)
 *  - send back wwsvc.log (same directory as the exe)
 *  - stop with Ctrl+C (console) -- the service deregisters (cmd5) on exit.
 *
 * New-driver mode (WWFilter minifilter, Phase 1):
 *  - run:  wwsvc.exe console -wwflt
 *  - starts the WWFilter driver, loads <installdir>\wwkrn.xcf, builds the
 *    policy (Kernel overlaid by the active User group) and pushes it to
 *    the driver via IOCTL_WWFLT_SET_POLICY, then drains the driver's
 *    event ring into wwflt.log until stopped. The old vendor channel
 *    (WWHost / wwkernel / waiters) is NOT touched in this mode.
 *  - server policy fetch is reserved: policy_fetch_from_server() in
 *    policy_build.c (returns "not configured" in Phase 1); the call site
 *    is in run_wwflt_body() below.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include "wwdrv.h"
#include "xcf.h"
#include "deflate_store.h"
#include "policy_build.h"
#include "wwflt_client.h"

/* main policy group name, GBK bytes for "主加密策略" (10 bytes).
 * NOTE: the policy takeover that used to move every User entry to this
 * group was removed in Phase 1 cleanup — wwsvc only reads wwkrn.xcf
 * now and never writes it. This constant is currently unused. */
static const uint8_t POLICY_MAIN_GBK[] = {
    0xd6, 0xf7, 0xbc, 0xd3, 0xc3, 0xdc, 0xb2, 0xdf, 0xc2, 0xd4
};

#define SVC_NAME "WWNewSvc"
#define SVC_DISPLAY "WaterWall New Client Service"
#define MUTEX_NAME "Global\\WWNewSvc-SingleInstance"
#define MAX_ENTRIES 16

static FILE *g_log = NULL;
static int g_console = 0;
static HANDLE g_hStop = NULL;      /* signalled to stop everything */
static HANDLE g_hHost = INVALID_HANDLE_VALUE;
static HANDLE g_hKrn = INVALID_HANDLE_VALUE;
static DWORD g_pid = 0;
static wchar_t g_exename[64] = L"wwsvc.exe";
static char g_install_dir[MAX_PATH] = "D:\\visteam\\wwall";
static char g_log_path[MAX_PATH] = { 0 };
static int g_wwflt = 0;          /* -wwflt: new WWFilter driver mode (no vendor channel) */

/* ---------- logging ---------- */
static void logf(const char *fmt, ...)
{
    char line[2048];
    va_list ap;
    SYSTEMTIME st;
    char ts[32];
    GetLocalTime(&st);
    snprintf(ts, sizeof(ts), "%04u-%02u-%02u %02u:%02u:%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (g_console) printf("[%s] %s\n", ts, line);
    if (g_log) {
        fprintf(g_log, "[%s] %s\n", ts, line);
        fflush(g_log);
    }
}

/* ---------- SCM: start a driver service if stopped ---------- */
static void scm_start_driver(const char *svc)
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) { logf("scm: OpenSCManager failed err=%lu", GetLastError()); return; }
    SC_HANDLE h = OpenServiceA(scm, svc, SERVICE_QUERY_STATUS | SERVICE_START);
    if (!h) {
        logf("scm: service '%s' not found err=%lu (driver not installed?)", svc, GetLastError());
        CloseServiceHandle(scm);
        return;
    }
    SERVICE_STATUS ss;
    if (!QueryServiceStatus(h, &ss)) {
        logf("scm: QueryServiceStatus '%s' failed err=%lu", svc, GetLastError());
    } else if (ss.dwCurrentState == SERVICE_RUNNING) {
        logf("scm: service '%s' already RUNNING", svc);
    } else {
        logf("scm: service '%s' state=%lu, starting...", svc, ss.dwCurrentState);
        if (StartServiceA(h, 0, NULL)) {
            /* wait up to 10 s for RUNNING */
            for (int i = 0; i < 20; i++) {
                Sleep(500);
                if (QueryServiceStatus(h, &ss) && ss.dwCurrentState == SERVICE_RUNNING) break;
            }
            logf("scm: service '%s' now state=%lu", svc, ss.dwCurrentState);
        } else {
            logf("scm: StartService '%s' failed err=%lu", svc, GetLastError());
        }
    }
    CloseServiceHandle(h);
    CloseServiceHandle(scm);
}

/* ---------- registry: read injection config, derive install dir ---------- */
static int read_inject_config(char *install_dir, size_t dir_cap)
{
    HKEY hkey;
    int found = 0;
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Services\\wwkernel", 0,
        KEY_READ | KEY_WOW64_64KEY, &hkey);
    if (rc != ERROR_SUCCESS) {
        logf("reg: cannot open wwkernel service key err=%ld", rc);
        return 0;
    }
    for (int i = 1; i <= 999; i++) {
        char name[16];
        uint8_t buf[8192];
        DWORD len = sizeof(buf), type = 0;
        snprintf(name, sizeof(name), "DLL %03d", i);
        rc = RegQueryValueExA(hkey, name, NULL, &type, buf, &len);
        if (rc != ERROR_SUCCESS) break;
        if (len < 4) continue;
        uint32_t total = 0;
        memcpy(&total, buf, 4);
        /* DLL path at +0x88, WCHAR[260] */
        wchar_t wpath[260] = { 0 };
        if (len >= 0x88 + 2) {
            memcpy(wpath, buf + 0x88, 0x208);
            wpath[259] = 0;
        }
        char mbpath[MAX_PATH] = { 0 };
        WideCharToMultiByte(CP_ACP, 0, wpath, -1, mbpath, sizeof(mbpath), NULL, NULL);
        logf("reg: %s total=%lu dll='%s'", name, total, mbpath);
        if (!found && mbpath[0]) {
            /* strip basename -> install dir */
            char *slash = strrchr(mbpath, '\\');
            if (slash && slash > mbpath) {
                size_t n = (size_t)(slash - mbpath);
                if (n < dir_cap) {
                    memcpy(install_dir, mbpath, n);
                    install_dir[n] = 0;
                    found = 1;
                }
            }
        }
    }
    RegCloseKey(hkey);
    if (!found) logf("reg: no DLL config entries found (clean machine? installer must write them)");
    return found;
}


/* ---------- USB policy from wwkrn.xcf ---------- */
static void apply_usb_policy(void)
{
    char xcf_path[MAX_PATH];
    xcf_t x;
    char usb[64] = { 0 };
    char wl[5000] = { 0 };
    DWORD flags0 = 0, flags1 = 0;
    int have_usb, have_wl;

    snprintf(xcf_path, sizeof(xcf_path), "%s\\wwkrn.xcf", g_install_dir);
    if (xcf_load(xcf_path, &x) != 0) {
        logf("usb: cannot load %s (config missing?) -- USB policy skipped, flags left as-is", xcf_path);
        return;
    }
    have_usb = xcf_get(&x, "Kernel", "usb", usb, sizeof(usb));
    have_wl = xcf_get(&x, "Kernel", "usb_white_list", wl, sizeof(wl));
    logf("usb: xcf Kernel/usb='%s' (%s), usb_white_list %s (len=%d)",
         have_usb ? usb : "(missing)", have_usb ? "found" : "not found",
         have_wl ? "present" : "absent", have_wl ? (int)strlen(wl) : 0);
    xcf_free(&x);

    if (!drv_read_flags(g_hHost, &flags0)) {
        logf("usb: 0x1e read flags failed -- aborting USB policy apply");
        return;
    }
    logf("usb: flags before = 0x%08lx (bit8 READ=%d bit9 CLOSE=%d)", flags0,
         (flags0 >> 8) & 1, (flags0 >> 9) & 1);

    /* normalise mode */
    for (char *p = usb; *p; p++) *p = (char)tolower((unsigned char)*p);
    const wchar_t *verb = L"USBPVG.OPEN";
    int need_wl = 0;
    if (strcmp(usb, "read") == 0 || strcmp(usb, "all_read") == 0) {
        verb = L"USBPVG.READ"; need_wl = (strcmp(usb, "read") == 0);
    } else if (strcmp(usb, "close") == 0 || strcmp(usb, "all_close") == 0) {
        verb = L"USBPVG.CLOSE"; need_wl = (strcmp(usb, "close") == 0);
    } else {
        /* "none" or unknown -> OPEN (clear bits) */
        verb = L"USBPVG.OPEN";
    }

    if (need_wl) {
        if (have_wl && wl[0]) {
            logf("usb: sending 0x26 whitelist (%d bytes, as stored in .xcf): '%s'",
                 (int)strlen(wl), wl);
            if (drv_send_whitelist(g_hHost, (const uint8_t *)wl, (DWORD)strlen(wl)))
                logf("usb: 0x26 whitelist accepted");
            else
                logf("usb: 0x26 whitelist REJECTED err=%lu (mode verb still applied below)", GetLastError());
        } else {
            logf("usb: WARNING mode needs a whitelist but .xcf has none -- verb applied, driver keeps its current whitelist");
        }
    } else {
        logf("usb: mode needs no whitelist, skipping 0x26");
    }

    {
        char mb[64];
        WideCharToMultiByte(CP_ACP, 0, verb, -1, mb, sizeof(mb), NULL, NULL);
        if (drv_send_verb(g_hHost, verb))
            logf("usb: 0x18 verb %s accepted", mb);
        else
            logf("usb: 0x18 verb %s REJECTED err=%lu", mb, GetLastError());
    }

    if (drv_read_flags(g_hHost, &flags1)) {
        logf("usb: flags after  = 0x%08lx (bit8 READ=%d bit9 CLOSE=%d) %s",
             flags1, (flags1 >> 8) & 1, (flags1 >> 9) & 1,
             (flags1 == flags0) ? "(unchanged)" : "(changed)");
    }
}

/* ---------- 0x22e014 waiter thread (one per entry) ---------- */
typedef struct {
    DWORD index;
    HANDLE hStop;
} waiter_arg_t;

static DWORD WINAPI waiter_thread(LPVOID param)
{
    waiter_arg_t *a = (waiter_arg_t *)param;
    HANDLE hSync = INVALID_HANDLE_VALUE;
    uint8_t *entry = NULL;
    DWORD entry_len = 0;
    ww_waiter_t w;

    logf("waiter[%lu]: starting (entry index %lu)", a->index, a->index);
    hSync = drv_open_kernel();
    if (hSync == INVALID_HANDLE_VALUE) {
        logf("waiter[%lu]: cannot open wwkernel device err=%lu", a->index, GetLastError());
        return 1;
    }
    entry = (uint8_t *)malloc(65536);
    if (!entry) { CloseHandle(hSync); return 1; }
    if (!drv_get_entry(hSync, a->index, entry, 65536, &entry_len)) {
        logf("waiter[%lu]: 0x22e010 failed (no such entry?) -- thread exits", a->index);
        free(entry);
        CloseHandle(hSync);
        return 1;
    }
    CloseHandle(hSync);
    logf("waiter[%lu]: entry total=%lu bytes", a->index, entry_len);

    memset(&w, 0, sizeof(w));
    w.hKrn = drv_open_kernel_overlapped();
    if (w.hKrn == INVALID_HANDLE_VALUE) {
        logf("waiter[%lu]: cannot open wwkernel device err=%lu", a->index, GetLastError());
        free(entry);
        return 1;
    }
    w.entry = entry;
    w.entry_len = entry_len;
    w.hStop = a->hStop;
    w.key = 0;

    for (;;) {
        int r = drv_wait_once(&w);
        if (r == -1) { logf("waiter[%lu]: stopped", a->index); break; }
        if (r == 0) {
            logf("waiter[%lu]: 0x22e014 failed err=%lu -- retry in 5 s", a->index, GetLastError());
            if (WaitForSingleObject(a->hStop, 5000) == WAIT_OBJECT_0) break;
            continue;
        }
        /* notified */
        logf("waiter[%lu]: INJECTED pid=%lu parent=%lu session=%lu flags=0x%08lx next_key=%lu",
             a->index, w.out5[0], w.out5[1], w.out5[2], w.out5[3], w.out5[4]);
        w.key = w.out5[4];
    }
    CloseHandle(w.hKrn);
    free(entry);
    return 0;
}

/* ---------- WWFilter driver mode (-wwflt) ---------- */
/* New-driver control plane: start the WWFilter minifilter, push the
 * policy built from the local .xcf, then drain the driver's event ring
 * into wwflt.log until stopped. The driver keeps enforcing the last
 * policy after this service exits (it is independent); we do NOT stop
 * the driver on exit.
 *
 * Reserved: policy_fetch_from_server() is tried first (Phase 1 returns
 * "not configured"); the local .xcf is the fallback. When the server
 * exists, that call will return a policy and the local .xcf becomes the
 * offline fallback. */
static void run_wwflt_body(void)
{
    HANDLE hFlt = INVALID_HANDLE_VALUE;
    char xcf_path[MAX_PATH];
    char group[128] = { 0 };
    char errbuf[256] = { 0 };
    WWFLT_POLICY *pol = NULL;
    WWFLT_POLICY *srv_pol = NULL;
    ULONG rule_count = 0;
    DWORD err;
    xcf_t x;
    WWFLT_EVENT events[256];
    ULONG ev_count = 0, ev_dropped = 0;
    int have_policy = 0;

    logf("=== wwflt mode: WWFilter minifilter driver (no vendor channel) ===");

    /* 1. start the driver */
    err = wwflt_start_driver();
    if (err != 0) {
        logf("wwflt: cannot start WWFilter driver err=%lu (is wwflt.sys installed?)", err);
        return;
    }
    logf("wwflt: driver started");
    hFlt = wwflt_open();
    if (hFlt == INVALID_HANDLE_VALUE) {
        logf("wwflt: cannot open \\\\.\\WWFilter err=%lu", GetLastError());
        return;
    }
    logf("wwflt: control device opened");
    wwflt_set_log_level(hFlt, 1);

    /* 2. policy: try the server first (reserved; Phase 1: not configured),
     * fall back to the local .xcf. */
    if (policy_fetch_from_server(NULL, &srv_pol, errbuf, sizeof(errbuf)) == 0) {
        pol = srv_pol;
        have_policy = 1;
        logf("wwflt: policy fetched from server");
    } else {
        logf("wwflt: server fetch unavailable (%s); using local .xcf", errbuf);
        snprintf(xcf_path, sizeof(xcf_path), "%s\\wwkrn.xcf", g_install_dir);
        if (xcf_load(xcf_path, &x) != 0) {
            logf("wwflt: cannot load %s -- no policy to push (driver passes everything through)", xcf_path);
            CloseHandle(hFlt);
            return;
        }
        if (policy_build_from_xcf(&x, &pol, &rule_count, group, sizeof(group), errbuf, sizeof(errbuf)) != 0) {
            logf("wwflt: policy build failed: %s", errbuf);
            xcf_free(&x);
            CloseHandle(hFlt);
            return;
        }
        xcf_free(&x);
        have_policy = 1;
        logf("wwflt: policy built from %s (group='%s', %lu process rules)", xcf_path, group, rule_count);
    }

    /* 3. push the policy to the driver */
    if (have_policy && pol) {
        err = wwflt_set_policy(hFlt, pol);
        if (err != 0) {
            logf("wwflt: SET_POLICY failed err=%lu", err);
        } else {
            WWFLT_STATUS st;
            logf("wwflt: policy pushed (version=%lu, %lu rules)", pol->version, pol->proc_count);
            if (wwflt_get_status(hFlt, &st) == 0) {
                logf("wwflt: status driver v%lu policy v%lu open_enc=%lu enc_bytes=%llu dec_bytes=%llu lookups=%llu errors=%llu",
                     st.driver_version, st.policy_version, st.encrypted_files_open,
                     st.bytes_encrypted, st.bytes_decrypted, st.policy_lookups, st.errors);
            }
        }
        free(pol);
        pol = NULL;
    }

    /* 4. drain the event ring until stopped */
    logf("wwflt: running (draining event ring to wwflt.log) -- press Ctrl+C or stop the service");
    while (WaitForSingleObject(g_hStop, 2000) == WAIT_TIMEOUT) {
        err = wwflt_get_events(hFlt, 256, events, &ev_count, &ev_dropped);
        if (err == 0 && ev_count > 0) {
            int n = wwflt_log_events_to_file("wwflt.log", events, ev_count);
            if (n > 0) logf("wwflt: %d event(s) logged (dropped=%lu)", n, ev_dropped);
        } else if (err != 0) {
            logf("wwflt: GET_EVENTS failed err=%lu", err);
        }
    }
    /* final drain */
    if (wwflt_get_events(hFlt, 256, events, &ev_count, &ev_dropped) == 0 && ev_count > 0) {
        wwflt_log_events_to_file("wwflt.log", events, ev_count);
    }
    logf("wwflt: stopping (driver keeps running with the last policy)");
    CloseHandle(hFlt);
}

/* ---------- main service body (shared by console + service mode) ---------- */
static void run_service_body(void)
{
    HANDLE hMutex = NULL;
    HANDLE hWaiters[MAX_ENTRIES];
    waiter_arg_t wargs[MAX_ENTRIES];
    int n_waiters = 0;
    DWORD d0 = 0, d1 = 0;

    logf("=== wwsvc starting (pid=%lu exe=%S) ===", g_pid, g_exename);
    logf("install dir: %s", g_install_dir);

    hMutex = CreateMutexA(NULL, FALSE, MUTEX_NAME);
    if (!hMutex) {
        logf("single-instance mutex failed err=%lu", GetLastError());
    } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
        logf("another wwsvc instance is already running -- exiting");
        return;
    }

    /* New-driver mode: skip the whole vendor channel (drivers, WWHost,
     * wwkernel, USB policy, waiters). The WWFilter driver is the engine. */
    if (g_wwflt) {
        run_wwflt_body();
        if (hMutex) CloseHandle(hMutex);
        logf("=== wwsvc stopped ===");
        return;
    }

    /* 1. drivers */
    scm_start_driver("wwkernel");
    scm_start_driver("WWHost");

    /* 2. injection config (read + verify; install dir from DLL path) */
    {
        char dir[MAX_PATH] = { 0 };
        if (read_inject_config(dir, sizeof(dir)) && dir[0]) {
            strncpy(g_install_dir, dir, sizeof(g_install_dir) - 1);
            logf("install dir (from registry): %s", g_install_dir);
        } else {
            logf("install dir: using default/override %s", g_install_dir);
        }
    }

    /* 3. WWHost channel */
    g_hHost = drv_open_host();
    if (g_hHost == INVALID_HANDLE_VALUE) {
        logf("FATAL: cannot open \\\\.\\Global\\WWHost err=%lu -- is the driver loaded?", GetLastError());
        goto cleanup;
    }
    logf("WWHost opened");
    if (drv_cmd1(g_hHost, &d0, &d1))
        logf("cmd1 probe OK: out=[0x%08lx, 0x%08lx]", d0, d1);
    else
        logf("cmd1 probe FAILED (d0=0x%08lx d1=0x%08lx) -- driver may be unhealthy", d0, d1);
    if (drv_register(g_hHost, g_pid, g_exename))
        logf("cmd3 self-register OK (pid=%lu)", g_pid);
    else
        logf("cmd3 self-register FAILED err=%lu", GetLastError());

    g_hKrn = drv_open_kernel();
    if (g_hKrn == INVALID_HANDLE_VALUE)
        logf("WARNING: cannot open \\\\.\\wwkernel err=%lu -- waiter threads will not run", GetLastError());
    else
        logf("wwkernel opened");

    /* 4. USB policy */
    apply_usb_policy();

    /* 5. USB device list (read-only, informational) */
    {
        uint8_t out[5000];
        DWORD ret = 0;
        if (drv_enum_usb(g_hHost, out, sizeof(out), &ret) && ret > 0) {
            DWORD pos = 0;
            int dev = 0;
            while (pos < ret) {
                char *s[4];
                int got = 1;
                for (int k = 0; k < 4; k++) {
                    if (pos >= ret) { got = 0; break; }
                    s[k] = (char *)(out + pos);
                    pos += (DWORD)strlen(s[k]) + 1;
                }
                if (!got) break;
                logf("usb dev %d: vendor='%s' product='%s' rev='%s' serial='%s'",
                     dev, s[0], s[1], s[2], s[3]);
                dev++;
            }
            if (dev == 0) logf("usb: no BusType==7 devices reported");
        } else {
            logf("usb: 0x27 enumerate returned nothing (ok, no USB storage attached?)");
        }
    }

    /* 6. waiter threads: one per entry index until 0x22e010 fails */
    if (g_hKrn != INVALID_HANDLE_VALUE) {
        for (DWORD idx = 0; idx < MAX_ENTRIES; idx++) {
            /* probe the entry first (cheap, sync) */
            uint8_t *tmp = (uint8_t *)malloc(65536);
            DWORD elen = 0;
            int ok = tmp && drv_get_entry(g_hKrn, idx, tmp, 65536, &elen);
            free(tmp);
            if (!ok) {
                logf("entries: index %lu has no entry -- %d waiter thread(s) started", idx, n_waiters);
                break;
            }
            wargs[n_waiters].index = idx;
            wargs[n_waiters].hStop = g_hStop;
            hWaiters[n_waiters] = CreateThread(NULL, 0, waiter_thread, &wargs[n_waiters], 0, NULL);
            if (hWaiters[n_waiters]) {
                logf("waiter[%lu]: thread started", idx);
                n_waiters++;
            } else {
                logf("waiter[%lu]: CreateThread failed err=%lu", idx, GetLastError());
            }
        }
    }

    logf("=== wwsvc running (transparent crypto is the vendor engine; no license code) ===");
    logf("press Ctrl+C (console) or stop the service to shut down cleanly");

    /* 7. wait for stop */
    WaitForSingleObject(g_hStop, INFINITE);
    logf("=== wwsvc stopping ===");

    /* wait for waiter threads to finish (they see hStop) */
    if (n_waiters > 0) {
        DWORD wr = WaitForMultipleObjects(n_waiters, hWaiters, TRUE, 15000);
        if (wr == WAIT_TIMEOUT) logf("waiter threads did not all exit in 15 s (proceeding anyway)");
        for (int i = 0; i < n_waiters; i++) CloseHandle(hWaiters[i]);
    }

cleanup:
    if (g_hHost != INVALID_HANDLE_VALUE) {
        if (drv_deregister(g_hHost, g_pid, g_exename))
            logf("cmd5 self-deregister OK");
        else
            logf("cmd5 self-deregister FAILED err=%lu (stale entry, harmless)", GetLastError());
        CloseHandle(g_hHost);
        g_hHost = INVALID_HANDLE_VALUE;
    }
    if (g_hKrn != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hKrn);
        g_hKrn = INVALID_HANDLE_VALUE;
    }
    if (hMutex) CloseHandle(hMutex);
    logf("=== wwsvc stopped ===");
}

/* ---------- service-mode glue ---------- */
static SERVICE_STATUS_HANDLE g_svc_status = NULL;
static SERVICE_STATUS g_svc_state;

static void svc_set_state(DWORD state, DWORD exit_code)
{
    g_svc_state.dwCurrentState = state;
    g_svc_state.dwWin32ExitCode = exit_code;
    g_svc_state.dwCheckPoint = 0;
    g_svc_state.dwWaitHint = 0;
    if (g_svc_status) SetServiceStatus(g_svc_status, &g_svc_state);
}

static void WINAPI svc_ctrl(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        svc_set_state(SERVICE_STOP_PENDING, NO_ERROR);
        SetEvent(g_hStop);
    }
}

static void WINAPI svc_main(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;
    memset(&g_svc_state, 0, sizeof(g_svc_state));
    g_svc_state.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_state.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svc_status = RegisterServiceCtrlHandlerA(SVC_NAME, svc_ctrl);
    if (!g_svc_status) return;
    svc_set_state(SERVICE_START_PENDING, NO_ERROR);
    svc_set_state(SERVICE_RUNNING, NO_ERROR);
    run_service_body();
    svc_set_state(SERVICE_STOPPED, NO_ERROR);
}

static BOOL WINAPI console_ctrl(DWORD ctrl)
{
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT || ctrl == CTRL_CLOSE_EVENT) {
        SetEvent(g_hStop);
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char **argv)
{
    char exepath[MAX_PATH];
    char *dir_arg = NULL;
    int want_console = 0;

    g_pid = GetCurrentProcessId();
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "console") == 0 || strcmp(argv[i], "-console") == 0 ||
            strcmp(argv[i], "-c") == 0) want_console = 1;
        else if (strcmp(argv[i], "-wwflt") == 0 ||
                 strcmp(argv[i], "--wwflt") == 0) g_wwflt = 1;
        else if (strncmp(argv[i], "-dir=", 5) == 0) dir_arg = argv[i] + 5;
        else if (strncmp(argv[i], "--dir=", 6) == 0) dir_arg = argv[i] + 6;
    }
    if (dir_arg && dir_arg[0]) {
        strncpy(g_install_dir, dir_arg, sizeof(g_install_dir) - 1);
    }

    GetModuleFileNameA(NULL, exepath, sizeof(exepath));
    {
        const char *base = strrchr(exepath, '\\');
        base = base ? base + 1 : exepath;
        /* log path = exe dir + wwsvc.log */
        size_t dlen = base ? (size_t)(base - exepath) : 0;
        if (dlen + 10 < sizeof(g_log_path)) {
            memcpy(g_log_path, exepath, dlen);
            g_log_path[dlen] = 0;
            strcat(g_log_path, "wwsvc.log");
        } else {
            snprintf(g_log_path, sizeof(g_log_path), "wwsvc.log");
        }
        MultiByteToWideChar(CP_ACP, 0, base, -1, g_exename, 64);
    }

    g_hStop = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_hStop) return 1;

    if (want_console) {
        g_console = 1;
        g_log = fopen(g_log_path, "a");
        SetConsoleCtrlHandler(console_ctrl, TRUE);
        logf("wwsvc console mode (log: %s)", g_log_path);
        run_service_body();
        if (g_log) fclose(g_log);
        return 0;
    }

    /* service mode: if SCM did not start us, fall back to console */
    {
        static const SERVICE_TABLE_ENTRYA table[] = {
            { (LPSTR)SVC_NAME, svc_main },
            { NULL, NULL }
        };
        g_log = fopen(g_log_path, "a");
        if (!StartServiceCtrlDispatcherA(table)) {
            DWORD err = GetLastError();
            if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                g_console = 1;
                SetConsoleCtrlHandler(console_ctrl, TRUE);
                logf("wwsvc console mode (not started by SCM; log: %s)", g_log_path);
                run_service_body();
            } else {
                logf("StartServiceCtrlDispatcher failed err=%lu", err);
            }
        }
        if (g_log) fclose(g_log);
    }
    return 0;
}
