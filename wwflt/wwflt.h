/* wwflt.h -- shared definitions for the WWFilter minifilter driver and
 * the user-mode service (wwsvc). Both sides include this file; the IOCTL
 * codes and the wire formats must stay in sync.
 *
 * Control device: \\Device\\WWFilter, symbolic link \\DosDevices\\WWFilter.
 * All IOCTLs use METHOD_BUFFERED.
 */
#pragma once

#define WWFLT_DEVICE_NAME      L"\\Device\\WWFilter"
#define WWFLT_DOS_DEVICE_NAME  L"\\DosDevices\\WWFilter"
#define WWFLT_WIN32_DEVICE     "\\\\.\\WWFilter"

/* ---- file format (matches the old client, so files stay compatible) ---- */
#define WWFLT_HEADER_SIZE      512
#define WWFLT_KEY_SIZE         32
#define WWFLT_MAGIC_SIZE       16
/* magic: 40 21 28 15 2a 2d 1b 20 23 30 1e 19 2f 22 16 40 */
#define WWFLT_MAGIC_BYTES      { 0x40,0x21,0x28,0x15,0x2a,0x2d,0x1b,0x20, \
                                 0x23,0x30,0x1e,0x19,0x2f,0x22,0x16,0x40 }
#define WWFLT_VERSION_1        1   /* base table A */
#define WWFLT_VERSION_2        2   /* base table B */
#define WWFLT_CURRENT_VERSION  WWFLT_VERSION_2
#define WWFLT_HEADER_VERSION_OFF  0x10
#define WWFLT_HEADER_POLICY_OFF   0x12   /* policy name, ASCII, NUL-terminated */
#define WWFLT_HEADER_KEY_OFF      0x30   /* 32-byte key, stored as-is */

/* ---- policy model (mirrors the .xcf policy) ---- */
#define WWFLT_ENCRYPT_NONE     0   /* no rule: never encrypt */
#define WWFLT_ENCRYPT_READ     1   /* decrypt on read only, never encrypt on save */
#define WWFLT_ENCRYPT_WRITE    2   /* encrypt on save (and decrypt on read) */

#define WWFLT_MAX_EXE_LEN      64    /* exe name, e.g. "notepad.exe" (WCHAR) */
#define WWFLT_MAX_EXT_LEN      16    /* one extension, e.g. "txt" (WCHAR) */
#define WWFLT_MAX_EXTS_PER_PROC 16   /* max extensions in one process's File list */
#define WWFLT_MAX_PATH_RULES   8     /* dir/wild/include rules per process */
#define WWFLT_MAX_PATH_RULE_LEN 260  /* one path rule (WCHAR) */
#define WWFLT_MAX_PROCESSES    192   /* max process rules in one policy table */
#define WWFLT_MAX_GROUP_LEN    64    /* policy group name (WCHAR) */

/* One process rule, as sent from the service to the driver. All strings
 * are WCHAR, NUL-terminated. ext_list is '|' separated, e.g. L"txt|pdf".
 * path_rules is an array of wildcard patterns ('*' and '?'); a file
 * matches if ANY rule matches its full path. If path_rule_count == 0,
 * every path matches. */
typedef struct _WWFLT_PROC_RULE {
    WCHAR exe[WWFLT_MAX_EXE_LEN];          /* e.g. L"notepad.exe" (lowercase compare) */
    ULONG encrypt_mode;                    /* WWFLT_ENCRYPT_* */
    WCHAR ext_list[WWFLT_MAX_EXTS_PER_PROC * (WWFLT_MAX_EXT_LEN + 1)];
    ULONG path_rule_count;
    WCHAR path_rules[WWFLT_MAX_PATH_RULES][WWFLT_MAX_PATH_RULE_LEN];
} WWFLT_PROC_RULE;

/* Whole policy table, as sent via IOCTL_WWFLT_SET_POLICY. The service
 * builds this from the local .xcf (or, later, from the server). */
typedef struct _WWFLT_POLICY {
    ULONG version;                         /* policy revision; driver rejects older */
    WCHAR group[WWFLT_MAX_GROUP_LEN];      /* e.g. L"主加密策略" */
    ULONG proc_count;
    WWFLT_PROC_RULE procs[WWFLT_MAX_PROCESSES];
} WWFLT_POLICY;

/* ---- driver status (IOCTL_WWFLT_GET_STATUS) ---- */
typedef struct _WWFLT_STATUS {
    ULONG driver_version;                  /* e.g. 1 */
    ULONG policy_version;                  /* version of the active policy table */
    ULONG encrypted_files_open;            /* stream contexts alive now */
    ULONGLONG bytes_encrypted;             /* cumulative */
    ULONGLONG bytes_decrypted;             /* cumulative */
    ULONGLONG policy_lookups;              /* create-time policy evaluations */
    ULONGLONG io_filtered;                 /* total read/write callbacks seen */
    ULONGLONG errors;                      /* failed operations counted */
} WWFLT_STATUS;

/* ---- event log (IOCTL_WWFLT_GET_EVENTS) ----
 * The driver keeps a fixed-size ring (no unbounded growth). Each event is
 * one of these. The service drains it and writes wwflt.log / uploads it.
 * No file content is ever logged. */
#define WWFLT_EVENT_CREATE     1
#define WWFLT_EVENT_READ       2
#define WWFLT_EVENT_WRITE      3
#define WWFLT_EVENT_ENCRYPT    4
#define WWFLT_EVENT_DECRYPT    5
#define WWFLT_EVENT_ERROR      6
#define WWFLT_EVENT_POLICY     7   /* policy installed / replaced */

#define WWFLT_MAX_EVENT_PATH   260

typedef struct _WWFLT_EVENT {
    ULONGLONG timestamp_100ns;             /* KeQuerySystemTime */
    ULONG type;                            /* WWFLT_EVENT_* */
    ULONG pid;                             /* requesting process id */
    WCHAR process[WWFLT_MAX_EXE_LEN];      /* requesting exe name */
    WCHAR path[WWFLT_MAX_EVENT_PATH];      /* file path (truncated if longer) */
    ULONGLONG offset;                      /* logical file offset */
    ULONG length;                          /* bytes */
    LONG status;                           /* NTSTATUS of the operation */
} WWFLT_EVENT;

/* ---- IOCTL codes ---- */
#define WWFLT_IOCTL_BASE       0x800
#define IOCTL_WWFLT_SET_POLICY   CTL_CODE(FILE_DEVICE_UNKNOWN, WWFLT_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWFLT_GET_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, WWFLT_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWFLT_GET_EVENTS   CTL_CODE(FILE_DEVICE_UNKNOWN, WWFLT_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWFLT_SET_LOG_LEVEL CTL_CODE(FILE_DEVICE_UNKNOWN, WWFLT_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWFLT_SET_CONFIG   CTL_CODE(FILE_DEVICE_UNKNOWN, WWFLT_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* GET_EVENTS input: how many events the caller wants at most. Output is
 * WWFLT_EVENT_COUNT followed by that many WWFLT_EVENT entries. */
typedef struct _WWFLT_EVENT_COUNT {
    ULONG count;                           /* events returned */
    ULONG dropped;                         /* events overwritten before being read */
} WWFLT_EVENT_COUNT;

/* SET_LOG_LEVEL input: a single ULONG (0=errors only, 1=crypto events,
 * 2=policy evaluations). SET_CONFIG input: WWFLT_CONFIG. */
typedef struct _WWFLT_CONFIG {
    ULONG enabled;                         /* 0 = driver passes everything through */
    ULONG reserved[7];
} WWFLT_CONFIG;
