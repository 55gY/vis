/* wwinj_client.h -- user-mode client for the WWInject driver control
 * device (\\.\WWInject). The service uses this to start the driver,
 * configure the engine DLL path (+ LoadLibraryW address), request
 * on-demand injection by PID, and read status. The driver is a pure
 * injector: it injects into every new process and knows nothing about
 * policy, so there is no target-list API.
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

/* Request an on-demand injection into `pid`. Returns 0 on success;
 * *status_out gets the driver's NTSTATUS for the attempt. */
DWORD wwinj_inject_pid(HANDLE h, ULONG pid, LONG *status_out);

/* Read driver status. Returns 0 on success, else Win32 error. */
DWORD wwinj_get_status(HANDLE h, WWINJ_STATUS *st);
