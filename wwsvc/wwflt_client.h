/* wwflt_client.h -- user-mode client for the WWFilter driver control
 * device (\\.\WWFilter). The service uses this to start the driver,
 * push the policy, and drain the event ring / status.
 *
 * Transport note: the driver only speaks IOCTL. The service is the one
 * that will (later) fetch policy from the server over wss/tcp/http and
 * push it here. The driver itself never does networking.
 */
#pragma once
#include <windows.h>
#include "../wwflt/wwflt.h"

/* Start the WWFilter driver service (SCM). Returns 0 on success, else a
 * Win32 error code. Safe to call when it is already running. */
DWORD wwflt_start_driver(void);

/* Stop the WWFilter driver service. Returns 0 on success, else Win32 error. */
DWORD wwflt_stop_driver(void);

/* Open the control device. Returns a HANDLE or INVALID_HANDLE_VALUE. */
HANDLE wwflt_open(void);

/* Push a whole policy table to the driver. Returns 0 on success, else Win32 error. */
DWORD wwflt_set_policy(HANDLE h, const WWFLT_POLICY *pol);

/* Read driver status. Returns 0 on success, else Win32 error. */
DWORD wwflt_get_status(HANDLE h, WWFLT_STATUS *st);

/* Drain up to `want` events from the driver ring. On success, *count_out
 * is the number of events written to `out` (each a WWFLT_EVENT), and
 * *dropped_out is the driver's dropped-event counter. Returns 0 on success. */
DWORD wwflt_get_events(HANDLE h, ULONG want, WWFLT_EVENT *out, ULONG *count_out, ULONG *dropped_out);

/* Set the driver log level (0=errors only, 1=crypto events, 2=policy). */
DWORD wwflt_set_log_level(HANDLE h, ULONG level);

/* Enable (1) or disable (0) the driver (pass-through when disabled). */
DWORD wwflt_set_enabled(HANDLE h, ULONG enabled);

/* Append drained events to a log file in readable form (one line each).
 * `log_path` is the file to append to. Returns the number of lines written. */
int wwflt_log_events_to_file(const char *log_path, const WWFLT_EVENT *events, ULONG count);
