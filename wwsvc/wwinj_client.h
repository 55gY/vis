/* wwinj_client.h -- user-mode client for the WWInject driver control
 * device (\\.\WWInject). The service uses this to start the driver,
 * configure the engine DLL path (+ LoadLibraryW address) and the
 * target exe list, request on-demand injection by PID, and read status.
 */
#pragma once
#include <windows.h>
#include "../wwinj/wwinj.h"

/* Start the WWInject driver service (SCM). Returns 0 on success, else a
 * Win32 error code. Safe to call when it is already running. */
DWORD wwinj_start_driver(void);

/* Stop the WWInject driver service. Returns 0 on success, else Win32 error. */
DWORD wwinj_stop_driver(void);

/* Open the control device. Returns a HANDLE or INVALID_HANDLE_VALUE. */
HANDLE wwinj_open(void);

/* Set the engine DLL path + LoadLibraryW address. Returns 0 on success. */
DWORD wwinj_set_dll_path(HANDLE h, const WCHAR *dll_path, ULONGLONG load_library_w);

/* Set the target exe list. Returns 0 on success. */
DWORD wwinj_set_targets(HANDLE h, const WWINJ_TARGETS *targets);

/* Request an on-demand injection into `pid`. Returns 0 on success;
 * *status_out gets the driver's NTSTATUS for the attempt. */
DWORD wwinj_inject_pid(HANDLE h, ULONG pid, LONG *status_out);

/* Read driver status. Returns 0 on success, else Win32 error. */
DWORD wwinj_get_status(HANDLE h, WWINJ_STATUS *st);
