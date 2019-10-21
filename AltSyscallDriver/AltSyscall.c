#include <ntifs.h>
#include <Basetsd.h>

#include "AltSyscall.h"


typedef
BOOLEAN
ALT_SYSCALL_HANDLER(
    _In_ PKTRAP_FRAME
);

typedef ALT_SYSCALL_HANDLER* PALT_SYSCALL_HANDLERD;
typedef NTSTATUS(*PsRegisterAltSystemCallHandler)(ALT_SYSCALL_HANDLER, int);

/* 
    Not in the WDK, we will obtain it dynamically. Second Parameter should be PROCESS_INFORMATION_CLASS, 
    for now we will hardcode the value to 0x64 which is the value necessary to enable SystemCall Handling in the process.
    We use Zw instead of Nt, because we need the PreviousMode to be KernelMode not UserMode
*/
typedef NTSTATUS (*ZwSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);

// Driver init and unload functions
DRIVER_INITIALIZE	DriverEntry;
DRIVER_UNLOAD		DriverUnload;

// Driver dispatch functions
_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH AltSyscallCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH AltSyscallDeviceControl;

NTSTATUS
RegisterSyscallHandler(
    ALT_SYSCALL_HANDLER CallbackFunction
);
_Success_(return == TRUE)
ALT_SYSCALL_HANDLER SystemCallCallback;


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, AltSyscallCreateClose)
#pragma alloc_text(PAGE, AltSyscallDeviceControl)
#pragma alloc_text(PAGE, RegisterSyscallHandler)
#endif // ALLOC_PRAGMA

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING  RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status;
    UNICODE_STRING  ntUnicodeString;
    UNICODE_STRING  ntWin32NameString;
    PDEVICE_OBJECT  deviceObject = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Driver loading started\n");

    RtlInitUnicodeString(&ntUnicodeString, ALT_SYSCALL_NT_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &ntUnicodeString,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);                

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Failed to create device: %#X\n", status);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AltSyscallCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AltSyscallCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AltSyscallDeviceControl;

    RtlInitUnicodeString(&ntWin32NameString, ALT_SYSCALL_DOS_DEVICE_NAME);

    status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Failed to create symbolic link: %#X\n", status);
        IoDeleteDevice(deviceObject);
    }
    /*
        The handler can only be registered one time, that's why we are doing it on the DriverEntry. 
        If we call PsRegisterAltSystemCallHandler with a handler already register we will get a Bug Check 0x1E0
        Also we must find a way to check if this handler is alredy set and a way to clear it
    */
    status = RegisterSyscallHandler(SystemCallCallback);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Error trying to register the Syscall handler\n");
        IoDeleteDevice(deviceObject);
    }

    return status;
}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT   DriverObject
)
{

    PAGED_CODE();

    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Driver unloading started\n");

    RtlInitUnicodeString(&uniWin32NameString, ALT_SYSCALL_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&uniWin32NameString);
    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Driver unloading finished\n");
}

NTSTATUS
AltSyscallCreateClose(
    PDEVICE_OBJECT  DeviceObject,
    PIRP            Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS
AltSyscallDeviceControl(
    PDEVICE_OBJECT  DeviceObject,
    PIRP            Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    PIO_STACK_LOCATION			pIoCurrStackLocation;
    NTSTATUS					status = STATUS_SUCCESS;
    ULONG						inBufLength;
    PHANDLE                     inBuf;
    HANDLE                      pHandle;
    CLIENT_ID					clientId;
    HANDLE                      processInfo;
    OBJECT_ATTRIBUTES           objectAttributes;
    UNICODE_STRING				funcName;
    ZwSetInformationProcess		pZwSetInformationProcess;

    pIoCurrStackLocation = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = pIoCurrStackLocation->Parameters.DeviceIoControl.InputBufferLength;

    if (!inBufLength) {
        status = STATUS_INVALID_PARAMETER;
        goto End;
    }

    switch (pIoCurrStackLocation->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_ALT_SYSCALL_DRIVER:
        inBuf = (PHANDLE) Irp->AssociatedIrp.SystemBuffer;

        clientId.UniqueProcess = *inBuf;
        clientId.UniqueThread = 0;
        InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Monitor process PID: %zu\n", (ULONG64)clientId.UniqueProcess);

        status = ZwOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &objectAttributes, &clientId);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Error getting HANDLE for process PID: %zu\n", (ULONG64)clientId.UniqueProcess);

            Irp->IoStatus.Information = 0;
            goto End;
        }

        RtlInitUnicodeString(&funcName, L"ZwSetInformationProcess");
        pZwSetInformationProcess = (ZwSetInformationProcess)MmGetSystemRoutineAddress(&funcName);
        if (NULL == pZwSetInformationProcess) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Failed obtaining address of ZwSetInformationProcess\n");

            ObCloseHandle(pHandle, KernelMode);
            Irp->IoStatus.Information = 0;
            goto End;
        }

        processInfo = (HANDLE)clientId.UniqueProcess;
        status = pZwSetInformationProcess(pHandle, 0x64, &processInfo, 1);
        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Error setting process information: %08X\n", status);

            ObCloseHandle(pHandle, KernelMode);
            Irp->IoStatus.Information = 0;
            goto End;
        }

        ObCloseHandle(pHandle, KernelMode);

        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;

        break;
    }

End:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

NTSTATUS
RegisterSyscallHandler(
    ALT_SYSCALL_HANDLER CallbackFunction
)
{
        PAGED_CODE();

        NTSTATUS                        status;
        UNICODE_STRING                  funcName;
        PsRegisterAltSystemCallHandler  pPsRegisterAltSystemCallHandler;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Registering Syscall handler\n");

        RtlInitUnicodeString(&funcName, L"PsRegisterAltSystemCallHandler");
        pPsRegisterAltSystemCallHandler = (PsRegisterAltSystemCallHandler)MmGetSystemRoutineAddress(&funcName);
        if (NULL == pPsRegisterAltSystemCallHandler) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Failed obtaining address of PsRegisterAltSystemCallHandler\n");

            return STATUS_PROCEDURE_NOT_FOUND;
        }
        status = pPsRegisterAltSystemCallHandler(&CallbackFunction, 1);

        if (!NT_SUCCESS(status)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[AltSyscall] Error registering Syscall Handler\n");

            return STATUS_UNSUCCESSFUL;
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Syscall handler registered successfully\n");

        return status;
}

BOOLEAN
SystemCallCallback(
    _In_ PKTRAP_FRAME    TrapFrame
)
{
    // Keeping the syscall number in a local variable, trying to print it directly from the trap frame crashes the process, that's weird, why!?
    ULONG64 SyscallNum = TrapFrame->Rax;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AltSyscall] Syscall handler -> Syscall(%#04llx)\n", SyscallNum);

    return TRUE;
}