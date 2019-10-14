#pragma once

#define ALT_SYSCALL_NT_DEVICE_NAME		L"\\Device\\AltSyscall"
#define ALT_SYSCALL_DOS_DEVICE_NAME		L"\\DosDevices\\AltSyscall"

#define IOCTL_ALT_SYSCALL_DRIVER\
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x993, METHOD_BUFFERED, FILE_ANY_ACCESS  )

#define DRIVER_NAME       L"AltSyscall.sys"
