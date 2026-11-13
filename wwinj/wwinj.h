/* wwinj.h -- shared definitions for the WWInject driver and the
 * user-mode service (wwsvc). Both sides include this file; the IOCTL
 * codes and the wire formats must stay in sync.
 *
 * Control device: \\Device\\WWInject, symbolic link \\DosDevices\\WWInject.
 * All IOCTLs use METHOD_BUFFERED.
 *
 * The driver is a pure injector: it injects wweng64.dll into EVERY new
 * process by queueing a user-mode APC (LoadLibraryW) to the process's
 * first thread. It does NOT know or care about policy -- no target
 * list, no .xcf, no group. The engine DLL decides per-process and
 * per-file whether to encrypt/decrypt (it reads wwkrn.xcf itself).
 * The service can also ask for an on-demand injection by PID.
 */
#pragma once

#define WWINJ_DEVICE_NAME      L"\\Device\\WWInject"
#define WWINJ_DOS_DEVICE_NAME  L"\\DosDevices\\WWInject"
#define WWINJ_WIN32_DEVICE     "\\\\.\\WWInject"

#define WWINJ_MAX_DLL_PATH     260

/* ---- IOCTL codes ---- */
#define WWINJ_IOCTL_BASE       0x800
#define IOCTL_WWINJ_SET_DLL_PATH CTL_CODE(FILE_DEVICE_UNKNOWN, WWINJ_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWINJ_INJECT_PID   CTL_CODE(FILE_DEVICE_UNKNOWN, WWINJ_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WWINJ_GET_STATUS   CTL_CODE(FILE_DEVICE_UNKNOWN, WWINJ_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* SET_DLL_PATH input: WWINJ_DLL_PATH (WCHAR path + LoadLibraryW address).
 * The LoadLibraryW address is taken from the service process; kernel32.dll
 * is mapped at the same base in all processes (per-boot ASLR slide), so
 * the address is valid in the target process too. */
typedef struct _WWINJ_DLL_PATH {
    WCHAR path[WWINJ_MAX_DLL_PATH];
    ULONGLONG load_library_w;   /* address of LoadLibraryW in kernel32.dll */
} WWINJ_DLL_PATH, *PWWINJ_DLL_PATH;

/* INJECT_PID input/output: WWINJ_INJECT (pid in, NTSTATUS out). */
typedef struct _WWINJ_INJECT {
    ULONG pid;
    LONG status;                /* NTSTATUS of the injection attempt */
} WWINJ_INJECT, *PWWINJ_INJECT;

/* GET_STATUS output. */
typedef struct _WWINJ_STATUS {
    ULONG driver_version;
    ULONG dll_path_set;         /* 1 if a DLL path has been configured */
    ULONGLONG processes_seen;   /* create-process notifications */
    ULONGLONG injections_queued;
    ULONGLONG injections_failed;
} WWINJ_STATUS, *PWWINJ_STATUS;
