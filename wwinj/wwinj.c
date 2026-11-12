/* wwinj.c -- WWInject driver. Watches for new processes whose image
 * name is in the target list and injects the engine DLL (wweng64.dll)
 * by queueing a user-mode APC (LoadLibraryW) to the process's first
 * thread. The service configures the DLL path (+ LoadLibraryW address)
 * and the target exe list via IOCTL, and can request an on-demand
 * injection by PID for processes that are already running.
 *
 * Notes:
 * - The DLL-path memory allocated in the target process is intentionally
 *   leaked (a few hundred bytes per injected process); there is no clean
 *   hook for "after LoadLibraryW returns" from the APC path.
 * - The APC runs when the target thread enters an alertable wait. For a
 *   freshly created process this happens during startup, well before the
 *   user opens a file. If the thread never waits alertably, the DLL is
 *   not loaded; the rundown routine frees the APC context in that case.
 * - Only x64.
 */
#include <ntddk.h>
#include "wwinj.h"

#define WWINJ_TAG 'jinW'
#define WWINJ_DRIVER_VERSION 1

/* The WDK 10.0.19041 ntddk.h in this configuration does not expose the
 * APC routine types, the KAPC_ENVIRONMENT enum, or (consequently) the
 * KeInitializeApc / KeInsertQueueApc declarations at all -- the CI
 * build fails with "PKNORMAL_ROUTINE / KAPC_ENVIRONMENT /
 * PKKERNEL_ROUTINE: undeclared identifier" while the KeInitializeApc
 * call itself only draws an implicit-declaration warning. So define
 * the types and declare the two functions from the documented
 * signatures (WWINJ_ prefixed types; the function names are the real
 * ntoskrnl exports, so they link from ntoskrnl.lib). The process
 * access rights are likewise not visible here, so define the two
 * values used (from winnt.h). */
typedef VOID (*WWINJ_PKNORMAL_ROUTINE)(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2);
typedef VOID (*WWINJ_PKKERNEL_ROUTINE)(struct _KAPC *Apc, WWINJ_PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2);
typedef VOID (*WWINJ_PKRUNDOWN_ROUTINE)(struct _KAPC *Apc);
typedef enum _WWINJ_KAPC_ENVIRONMENT {
    WwinjOriginalApcEnvironment = 0,
    WwinjAttachedApcEnvironment,
    WwinjCurrentApcEnvironment,
    WwinjInsertApcEnvironment
} WWINJ_KAPC_ENVIRONMENT;
VOID KeInitializeApc(struct _KAPC *Apc, struct _KTHREAD *Thread, WWINJ_KAPC_ENVIRONMENT Environment, WWINJ_PKKERNEL_ROUTINE KernelRoutine, WWINJ_PKRUNDOWN_ROUTINE RundownRoutine, WWINJ_PKNORMAL_ROUTINE NormalRoutine, KPROCESSOR_MODE ProcessorMode, PVOID NormalContext);
BOOLEAN KeInsertQueueApc(struct _KAPC *Apc, PVOID SystemArgument1, PVOID SystemArgument2, KPRIORITY Increment);
#define WWINJ_ORIGINAL_APC_ENVIRONMENT WwinjOriginalApcEnvironment
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION 0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE 0x0020
#endif
/* SYSTEM_INFORMATION_CLASS value for SystemProcessInformation (=5);
 * the enum is not exposed by ntddk.h in this config. */
#define WWINJ_SYSTEM_PROCESS_INFORMATION_CLASS 5

/* ---- globals ---- */
static PDEVICE_OBJECT gDevice = NULL;
static WCHAR gDllPath[WWINJ_MAX_DLL_PATH] = { 0 };
static PVOID gLoadLibraryW = NULL;
static WCHAR gTargets[WWINJ_MAX_TARGETS][WWINJ_MAX_EXE_LEN];
static ULONG gTargetCount = 0;
static KSPIN_LOCK gCfgLock;
static ULONGLONG gProcessesSeen = 0;
static ULONGLONG gInjectionsQueued = 0;
static ULONGLONG gInjectionsFailed = 0;

/* PIDs already injected (avoid double injection). Small fixed table. */
#define WWINJ_MAX_INJECTED 256
static HANDLE gInjectedPids[WWINJ_MAX_INJECTED];
static ULONG gInjectedCount = 0;
static KSPIN_LOCK gInjectedLock;

static BOOLEAN WwInjAlreadyInjected(HANDLE pid)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&gInjectedLock, &irql);
    for (i = 0; i < gInjectedCount; i++) {
        if (gInjectedPids[i] == pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&gInjectedLock, irql);
    return found;
}

static void WwInjMarkInjected(HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&gInjectedLock, &irql);
    if (gInjectedCount < WWINJ_MAX_INJECTED) {
        gInjectedPids[gInjectedCount++] = pid;
    }
    KeReleaseSpinLock(&gInjectedLock, irql);
}

static WCHAR WwInjToLower(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') return (WCHAR)(c + (L'a' - L'A'));
    return c;
}

static int WwInjWcsIcmp(PCWSTR a, PCWSTR b)
{
    while (*a && *b) {
        WCHAR ca = WwInjToLower(*a), cb = WwInjToLower(*b);
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)WwInjToLower(*a) - (int)WwInjToLower(*b);
}

static BOOLEAN WwInjIsTarget(PCWSTR imageName)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;
    PCWSTR slash;
    PCWSTR base;
    if (!imageName) return FALSE;
    slash = wcsrchr(imageName, L'\\');
    base = slash ? slash + 1 : imageName;
    KeAcquireSpinLock(&gCfgLock, &irql);
    for (i = 0; i < gTargetCount; i++) {
        if (WwInjWcsIcmp(gTargets[i], base) == 0) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&gCfgLock, irql);
    return found;
}

/* ---- APC injection ---- */
typedef struct _WWINJ_APC_CTX {
    KAPC apc;
    PEPROCESS process;
    PVOID remotePath;   /* DLL path string in the target process */
    SIZE_T remoteSize;
} WWINJ_APC_CTX, *PWWINJ_APC_CTX;

static VOID WwInjApcKernelRoutine(PKAPC Apc, WWINJ_PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    /* Nothing to do before the user-mode routine runs. */
}

static VOID WwInjApcRundownRoutine(PKAPC Apc)
{
    PWWINJ_APC_CTX ctx = CONTAINING_RECORD(Apc, WWINJ_APC_CTX, apc);
    /* The APC was cancelled (thread exited before it ran). Free the
     * remote path memory if we can, then the context. */
    if (ctx->remotePath && ctx->process) {
        HANDLE hProc = NULL;
        NTSTATUS st = ObOpenObjectByPointer(ctx->process, OBJ_KERNEL_HANDLE,
            NULL, PROCESS_VM_OPERATION, *PsProcessType, KernelMode, &hProc);
        if (NT_SUCCESS(st)) {
            SIZE_T sz = 0;
            PVOID base = ctx->remotePath;
            ZwFreeVirtualMemory(hProc, &base, &sz, MEM_RELEASE);
            ZwClose(hProc);
        }
    }
    if (ctx->process) ObDereferenceObject(ctx->process);
    ExFreePoolWithTag(ctx, WWINJ_TAG);
}

/* Queue a LoadLibraryW APC to `thread` in `process`. The DLL path is
 * copied into the target process first. Returns an NTSTATUS. */
static NTSTATUS WwInjInjectThread(PEPROCESS process, PETHREAD thread)
{
    NTSTATUS st;
    HANDLE hProc = NULL;
    PVOID remote = NULL;
    SIZE_T pathBytes;
    SIZE_T regionSize;
    PWWINJ_APC_CTX ctx = NULL;
    KIRQL irql;
    WCHAR localPath[WWINJ_MAX_DLL_PATH];
    PVOID loadLibrary;

    KeAcquireSpinLock(&gCfgLock, &irql);
    if (!gDllPath[0] || !gLoadLibraryW) {
        KeReleaseSpinLock(&gCfgLock, irql);
        return STATUS_INVALID_PARAMETER;
    }
    wcsncpy(localPath, gDllPath, WWINJ_MAX_DLL_PATH - 1);
    localPath[WWINJ_MAX_DLL_PATH - 1] = L'\0';
    loadLibrary = gLoadLibraryW;
    KeReleaseSpinLock(&gCfgLock, irql);

    pathBytes = (wcslen(localPath) + 1) * sizeof(WCHAR);
    regionSize = pathBytes;

    st = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(st)) return st;

    st = ZwAllocateVirtualMemory(hProc, &remote, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) {
        ZwClose(hProc);
        return st;
    }
    /* Write the DLL path into the target process. MmCopyVirtualMemory
     * is the kernel-mode copy primitive (ZwWriteVirtualMemory is not
     * exported by ntoskrnl.lib in this WDK config). */
    {
        SIZE_T written = 0;
        st = MmCopyVirtualMemory(PsGetCurrentProcess(), localPath,
            process, remote, pathBytes, KernelMode, &written);
        if (!NT_SUCCESS(st) || written != pathBytes) {
            SIZE_T sz = 0;
            PVOID base = remote;
            ZwFreeVirtualMemory(hProc, &base, &sz, MEM_RELEASE);
            ZwClose(hProc);
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
        }
    }
    ZwClose(hProc);

    ctx = (PWWINJ_APC_CTX)ExAllocatePoolWithTag(NonPagedPool, sizeof(WWINJ_APC_CTX), WWINJ_TAG);
    if (!ctx) {
        /* Free the remote memory (best effort). */
        HANDLE hp2 = NULL;
        if (NT_SUCCESS(ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_VM_OPERATION, *PsProcessType, KernelMode, &hp2))) {
            SIZE_T sz = 0;
            PVOID base = remote;
            ZwFreeVirtualMemory(hp2, &base, &sz, MEM_RELEASE);
            ZwClose(hp2);
        }
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(ctx, sizeof(*ctx));
    ObReferenceObject(process);
    ctx->process = process;
    ctx->remotePath = remote;
    ctx->remoteSize = regionSize;

    KeInitializeApc(&ctx->apc, thread, WWINJ_ORIGINAL_APC_ENVIRONMENT,
        WwInjApcKernelRoutine, WwInjApcRundownRoutine,
        (WWINJ_PKNORMAL_ROUTINE)loadLibrary, UserMode, remote);
    if (!KeInsertQueueApc(&ctx->apc, NULL, NULL, 0)) {
        /* The thread is exiting; the rundown routine will free ctx. */
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

/* ---- thread lookup (PsGetNextProcessThread is not in ntoskrnl.lib
 * in this WDK config): find the first thread of a process by PID via
 * ZwQuerySystemInformation(SystemProcessInformation). ---- */
typedef struct _WWINJ_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
} WWINJ_SYSTEM_THREAD_INFORMATION, *PWWINJ_SYSTEM_THREAD_INFORMATION;

typedef struct _WWINJ_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
    WWINJ_SYSTEM_THREAD_INFORMATION Threads[1];
} WWINJ_SYSTEM_PROCESS_INFORMATION, *PWWINJ_SYSTEM_PROCESS_INFORMATION;

/* Find the first thread of the process `pid`. Returns an NTSTATUS and,
 * on success, a referenced PETHREAD in *thread_out. */
static NTSTATUS WwInjFindFirstThread(HANDLE pid, PETHREAD *thread_out)
{
    NTSTATUS st;
    ULONG size = 256 * 1024;
    PVOID buf = NULL;
    ULONG needed = 0;
    PWWINJ_SYSTEM_PROCESS_INFORMATION proc;
    *thread_out = NULL;

    buf = ExAllocatePoolWithTag(PagedPool, size, WWINJ_TAG);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    st = ZwQuerySystemInformation(WWINJ_SYSTEM_PROCESS_INFORMATION_CLASS, buf, size, &needed);
    if (st == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buf, WWINJ_TAG);
        size = needed;
        buf = ExAllocatePoolWithTag(PagedPool, size, WWINJ_TAG);
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
        st = ZwQuerySystemInformation(WWINJ_SYSTEM_PROCESS_INFORMATION_CLASS, buf, size, &needed);
    }
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(buf, WWINJ_TAG);
        return st;
    }
    proc = (PWWINJ_SYSTEM_PROCESS_INFORMATION)buf;
    for (;;) {
        if (proc->UniqueProcessId == pid && proc->NumberOfThreads > 0) {
            HANDLE tid = proc->Threads[0].ClientId.UniqueThread;
            st = PsLookupThreadByThreadId(tid, thread_out);
            ExFreePoolWithTag(buf, WWINJ_TAG);
            return st;
        }
        if (proc->NextEntryOffset == 0) break;
        /* Never walk past the end of the buffer: a corrupt or
         * truncated entry chain must not turn into an out-of-bounds
         * read (that is an access-violation BSOD). */
        if (proc->NextEntryOffset > size - ((PUCHAR)proc - (PUCHAR)buf)) break;
        proc = (PWWINJ_SYSTEM_PROCESS_INFORMATION)((PUCHAR)proc + proc->NextEntryOffset);
    }
    ExFreePoolWithTag(buf, WWINJ_TAG);
    return STATUS_NOT_FOUND;
}

/* Try to inject into `process` via its first thread. */
static NTSTATUS WwInjInjectProcess(PEPROCESS process)
{
    PETHREAD thread = NULL;
    NTSTATUS st;
    HANDLE pid = PsGetProcessId(process);
    st = WwInjFindFirstThread(pid, &thread);
    if (!NT_SUCCESS(st)) return st;
    st = WwInjInjectThread(process, thread);
    ObDereferenceObject(thread);
    return st;
}

/* ---- process / thread notifications ---- */
static VOID WwInjCreateProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    if (!CreateInfo) return; /* process exit */
    InterlockedIncrement64((volatile LONGLONG *)&gProcessesSeen);
    /* ImageFileName can be NULL for some creations; never deref it blind. */
    if (!CreateInfo->ImageFileName || !CreateInfo->ImageFileName->Buffer) return;
    if (!WwInjIsTarget(CreateInfo->ImageFileName->Buffer)) return;
    if (WwInjAlreadyInjected(ProcessId)) return;
    /* The initial thread may not exist yet; the thread notify below
     * does the actual injection when it appears. Marking here only
     * prevents duplicate attempts from racing notifications. */
}

static VOID WwInjCreateThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    PEPROCESS process = NULL;
    PETHREAD thread = NULL;
    NTSTATUS st;
    PUNICODE_STRING image = NULL;
    KIRQL irql;
    if (!Create) return;
    /* Skip everything until the service has configured a DLL path and
     * at least one target; otherwise every thread creation in the
     * system pays for a lookup and an injection attempt. */
    KeAcquireSpinLock(&gCfgLock, &irql);
    {
        BOOLEAN configured = (gDllPath[0] != 0) && (gLoadLibraryW != NULL) && (gTargetCount > 0);
        KeReleaseSpinLock(&gCfgLock, irql);
        if (!configured) return;
    }
    if (WwInjAlreadyInjected(ProcessId)) return;
    st = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(st)) return;
    st = SeLocateProcessImageName(process, &image);
    if (!NT_SUCCESS(st) || !image || !image->Buffer) {
        if (image) ExFreePool(image);
        ObDereferenceObject(process);
        return;
    }
    if (!WwInjIsTarget(image->Buffer)) {
        ExFreePool(image);
        ObDereferenceObject(process);
        return;
    }
    ExFreePool(image);
    /* Inject via this thread. Mark first so a second thread notify
     * for the same process does not queue a duplicate APC. */
    WwInjMarkInjected(ProcessId);
    /* Use the thread being created directly (PsLookupThreadByThreadId
     * on the notify's ThreadId). Do NOT enumerate all processes with
     * ZwQuerySystemInformation here: it is heavy, takes the process
     * list lock while a thread is being created, and can hand back a
     * thread that is not fully initialised -- that is the 0x3B crash
     * path. The ZwQuerySystemInformation lookup stays only in the
     * IOCTL INJECT_PID path for already-running processes. */
    st = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(st)) {
        InterlockedIncrement64((volatile LONGLONG *)&gInjectionsFailed);
        ObDereferenceObject(process);
        return;
    }
    st = WwInjInjectThread(process, thread);
    ObDereferenceObject(thread);
    if (NT_SUCCESS(st)) {
        InterlockedIncrement64((volatile LONGLONG *)&gInjectionsQueued);
    } else {
        InterlockedIncrement64((volatile LONGLONG *)&gInjectionsFailed);
    }
    ObDereferenceObject(process);
}

/* ---- device I/O ---- */
static NTSTATUS WwInjDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    NTSTATUS st = STATUS_SUCCESS;
    ULONG inLen, outLen;
    PVOID inBuf, outBuf;
    ULONG code;

    UNREFERENCED_PARAMETER(DeviceObject);
    irpSp = IoGetCurrentIrpStackLocation(Irp);
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    inBuf = Irp->AssociatedIrp.SystemBuffer;
    outBuf = Irp->AssociatedIrp.SystemBuffer;

    switch (code) {
    case IOCTL_WWINJ_SET_DLL_PATH: {
        PWWINJ_DLL_PATH p = (PWWINJ_DLL_PATH)inBuf;
        KIRQL irql;
        if (inLen < sizeof(WWINJ_DLL_PATH)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        KeAcquireSpinLock(&gCfgLock, &irql);
        wcsncpy(gDllPath, p->path, WWINJ_MAX_DLL_PATH - 1);
        gDllPath[WWINJ_MAX_DLL_PATH - 1] = L'\0';
        gLoadLibraryW = (PVOID)(ULONG_PTR)p->load_library_w;
        KeReleaseSpinLock(&gCfgLock, irql);
        Irp->IoStatus.Information = 0;
        break;
    }
    case IOCTL_WWINJ_SET_TARGETS: {
        PWWINJ_TARGETS t = (PWWINJ_TARGETS)inBuf;
        KIRQL irql;
        ULONG i;
        if (inLen < sizeof(ULONG) || inLen < sizeof(WWINJ_TARGETS)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        if (t->count > WWINJ_MAX_TARGETS) { st = STATUS_INVALID_PARAMETER; break; }
        KeAcquireSpinLock(&gCfgLock, &irql);
        gTargetCount = t->count;
        for (i = 0; i < t->count; i++) {
            wcsncpy(gTargets[i], t->exe[i], WWINJ_MAX_EXE_LEN - 1);
            gTargets[i][WWINJ_MAX_EXE_LEN - 1] = L'\0';
        }
        KeReleaseSpinLock(&gCfgLock, irql);
        Irp->IoStatus.Information = 0;
        break;
    }
    case IOCTL_WWINJ_INJECT_PID: {
        PWWINJ_INJECT req = (PWWINJ_INJECT)inBuf;
        PEPROCESS process = NULL;
        if (inLen < sizeof(WWINJ_INJECT) || outLen < sizeof(WWINJ_INJECT)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req->pid, &process);
        if (!NT_SUCCESS(st)) {
            req->status = (LONG)st;
            Irp->IoStatus.Information = sizeof(WWINJ_INJECT);
            st = STATUS_SUCCESS;
            break;
        }
        st = WwInjInjectProcess(process);
        ObDereferenceObject(process);
        if (NT_SUCCESS(st)) {
            InterlockedIncrement64((volatile LONGLONG *)&gInjectionsQueued);
            WwInjMarkInjected((HANDLE)(ULONG_PTR)req->pid);
        } else {
            InterlockedIncrement64((volatile LONGLONG *)&gInjectionsFailed);
        }
        req->status = (LONG)st;
        Irp->IoStatus.Information = sizeof(WWINJ_INJECT);
        st = STATUS_SUCCESS;
        break;
    }
    case IOCTL_WWINJ_GET_STATUS: {
        PWWINJ_STATUS s = (PWWINJ_STATUS)outBuf;
        KIRQL irql;
        if (outLen < sizeof(WWINJ_STATUS)) { st = STATUS_BUFFER_TOO_SMALL; break; }
        RtlZeroMemory(s, sizeof(*s));
        s->driver_version = WWINJ_DRIVER_VERSION;
        KeAcquireSpinLock(&gCfgLock, &irql);
        s->dll_path_set = gDllPath[0] ? 1 : 0;
        s->target_count = gTargetCount;
        KeReleaseSpinLock(&gCfgLock, irql);
        s->processes_seen = gProcessesSeen;
        s->injections_queued = gInjectionsQueued;
        s->injections_failed = gInjectionsFailed;
        Irp->IoStatus.Information = sizeof(WWINJ_STATUS);
        break;
    }
    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }
    Irp->IoStatus.Status = st;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS WwInjCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID WwInjUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    PsRemoveCreateThreadNotifyRoutine(WwInjCreateThreadNotify);
    PsSetCreateProcessNotifyRoutine(WwInjCreateProcessNotify, TRUE);
    RtlInitUnicodeString(&symLink, WWINJ_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symLink);
    if (gDevice) IoDeleteDevice(gDevice);
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    UNICODE_STRING devName, symLink;
    PDEVICE_OBJECT dev = NULL;
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&gCfgLock);
    KeInitializeSpinLock(&gInjectedLock);

    RtlInitUnicodeString(&devName, WWINJ_DEVICE_NAME);
    st = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    gDevice = dev;

    RtlInitUnicodeString(&symLink, WWINJ_DOS_DEVICE_NAME);
    st = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(dev);
        gDevice = NULL;
        return st;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = WwInjCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = WwInjCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WwInjDeviceControl;
    DriverObject->DriverUnload = WwInjUnload;

    st = PsSetCreateProcessNotifyRoutine(WwInjCreateProcessNotify, FALSE);
    if (!NT_SUCCESS(st)) {
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(dev);
        gDevice = NULL;
        return st;
    }
    st = PsSetCreateThreadNotifyRoutine(WwInjCreateThreadNotify);
    if (!NT_SUCCESS(st)) {
        PsSetCreateProcessNotifyRoutine(WwInjCreateProcessNotify, TRUE);
        IoDeleteSymbolicLink(&symLink);
        IoDeleteDevice(dev);
        gDevice = NULL;
        return st;
    }
    return STATUS_SUCCESS;
}
