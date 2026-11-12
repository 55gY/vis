/* wwdrv.h -- WaterWall driver channel (wwhost.sys + wwkernel.sys).
 * All formats are from the live-verified probes (wwprobe1/2/2b/3) and the
 * Phase 2/3 decompilation. Two channels:
 *  - Registration channel (wwhost.sys, \\.\Global\WWHost): small integer
 *    commands (1 probe, 3 ADD, 5 NOT, 0x18 USB verb, 0x1e flags, 0x27 USB
 *    enumerate, 0x26 whitelist). Plain DeviceIoControl, no encoding.
 *  - Injection control channel (wwkernel.sys, \\.\wwkernel): IOCTL
 *    0x22e000 family, RIPEMD-160 + session-byte encoded messages
 *    ([4B total][20B digest][encoded payload]).
 * The service NEVER uses 0x22e000/004/01c (dead on this build: the driver
 * validates the raw config message against the encoded line message and
 * the length check always fails). Config changes go through the registry.
 */
#ifndef WW_DRV_H
#define WW_DRV_H
#include <windows.h>
#include <stdint.h>

#define WW_MAGIC_W L"@#9357!$"

/* --- registration channel (WWHost) --- */
HANDLE drv_open_host(void);
HANDLE drv_open_kernel(void);
HANDLE drv_open_kernel_overlapped(void);
int drv_cmd1(HANDLE h, DWORD *d0, DWORD *d1);
int drv_register(HANDLE h, DWORD pid, const wchar_t *exename);
int drv_deregister(HANDLE h, DWORD pid, const wchar_t *exename);
int drv_read_flags(HANDLE h, DWORD *flags);
int drv_send_verb(HANDLE h, const wchar_t *verb);
int drv_send_whitelist(HANDLE h, const uint8_t *list, DWORD len);
int drv_enum_usb(HANDLE h, uint8_t *out, DWORD out_cap, DWORD *ret_len);

/* --- 0x22e000 encoding --- */
/* Encode payload into a line message. out must hold 0x18 + payload_len. */
DWORD drv_encode_msg(const uint8_t *payload, DWORD payload_len,
                     uint8_t *out, uint8_t tid_low);

/* --- injection control channel (wwkernel) --- */
/* 0x22e010: get entry <index> bytes. Returns 1 on success; *entry_len is
 * the entry's own total length (first DWORD of the output). */
int drv_get_entry(HANDLE h, DWORD index, uint8_t *out, DWORD out_cap,
                  DWORD *entry_len);

/* 0x22e014 waiter: register a waiter on one entry (inner = entry bytes).
 * Blocks on the overlapped event until a matching process is notified or
 * hStop is signalled. On notification fills the 5 output DWORDs
 * (new pid, parent pid, session id, flags, next key) and returns 1.
 * Returns 0 on error, -1 when asked to stop. The caller re-issues the
 * wait after each notification (chaining next_key as the new key). */
typedef struct {
    HANDLE hKrn;            /* \\.\wwkernel opened with FILE_FLAG_OVERLAPPED */
    const uint8_t *entry;   /* entry bytes (from drv_get_entry) */
    DWORD entry_len;
    HANDLE hStop;           /* signalled to cancel the wait */
    DWORD key;              /* key for this wait (0 first time) */
    DWORD out5[5];          /* notification output */
} ww_waiter_t;
int drv_wait_once(ww_waiter_t *w);

#endif
