#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>

#include <windef.h>

#include <wdf.h>

// bcdedit /set testsigning on
// bcdedit /set nointegritychecks on
// bcdedit /debug on

// sc.exe create TitanKMD binPath="*.sys" type=kernel

// copy kdnet.exe VerifiedNICList.xml
// kdnet.exe <HOST-IP> <PORT>
// windbg -k net:port=50954,key=383hvuxoesn3o.3p2a8necf4mb8.399q3owp0kuel.3p4c2qi1n7v5w

#define LOG(MSG, ...) DbgPrintEx(0, 0, "[TitanKMD] " MSG, __VA_ARGS__)

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

UNICODE_STRING sDeviceName;
UNICODE_STRING sWin32Device;

typedef struct _KERNEL_READ_REQUEST
{
  DWORD pid;
  UINT_PTR base;
  SIZE_T size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;
typedef struct _KERNEL_WRITE_REQUEST
{
  DWORD pid;
  UINT_PTR base;
  SIZE_T size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
  IoDeleteSymbolicLink(&sWin32Device);
  IoDeleteDevice(pDriverObject->DeviceObject);

  LOG("Driver unloaded\n");
}

NTSTATUS Read(PKERNEL_READ_REQUEST pReadRequest)
{
  NTSTATUS status = STATUS_SUCCESS;
  HANDLE pProcess = NULL;
  PEPROCESS pPe32 = NULL;

  LOG("Pid: %d\n", pReadRequest->pid);
  LOG("Base: %p\n", (PVOID)pReadRequest->base);
  LOG("Size: %ul\n", pReadRequest->size);

  status = PsLookupProcessByProcessId((HANDLE)pReadRequest->pid, &pPe32);

  if (NT_SUCCESS(status))
  {
    status = ObOpenObjectByPointer(pPe32, 0, NULL, STANDARD_RIGHTS_ALL, *PsProcessType, KernelMode, &pProcess);

    if (NT_SUCCESS(status))
    {
      status = ZwTerminateProcess(pProcess, 0);

      if (NT_SUCCESS(status))
      {
        LOG("Process %d terminated\n", pReadRequest->pid);
      }

      status = ZwClose(pProcess);
    }
    else
    {
      LOG("Invalid process handle\n");
    }
  }

  return status;
}
NTSTATUS Write(PKERNEL_WRITE_REQUEST pWriteRequest)
{
  NTSTATUS status = STATUS_SUCCESS;

  return status;
}

NTSTATUS EventDefaultHandler(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
  UNREFERENCED_PARAMETER(pDeviceObject);
  pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return pIrp->IoStatus.Status;
}
NTSTATUS EventCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
  UNREFERENCED_PARAMETER(pDeviceObject);
  pIrp->IoStatus.Status = STATUS_SUCCESS;
  pIrp->IoStatus.Information = 0;
  IoCompleteRequest(pIrp, IO_NO_INCREMENT);
  return pIrp->IoStatus.Status;
}
/*
NTSTATUS EventWrite(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
  UNREFERENCED_PARAMETER(pDeviceObject);

  NTSTATUS status = STATUS_SUCCESS;
  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(pIrp);

  if (pIoStackIrp)
  {
    switch (controlCode)
    {
      case IO_READ_REQUEST:
      {
        status = Read((PKERNEL_READ_REQUEST)pIrp->AssociatedIrp.SystemBuffer);
        LOG("Received read control\n");
        break;
      }
      case IO_WRITE_REQUEST:
      {
        status = Write((PKERNEL_WRITE_REQUEST)pIrp->AssociatedIrp.SystemBuffer);
        LOG("Received write control\n");
        break;
      }
      default:
      {
        status = STATUS_INVALID_PARAMETER;
        LOG("Unknown request control\n");
        break;
      }
    }
  }
  else
  {
    status = STATUS_UNSUCCESSFUL;
    LOG("Invalid IRP stack pointer\n");
  }
  
  pIrp->IoStatus.Status = status;
  pIrp->IoStatus.Information = 0;

  IoCompleteRequest(pIrp, IO_NO_INCREMENT);

  return pIrp->IoStatus.Status;
}
*/
NTSTATUS EventIoControl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
  UNREFERENCED_PARAMETER(pDeviceObject);

  NTSTATUS status = STATUS_SUCCESS;
  PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(pIrp);

  ULONG controlCode = pIoStackIrp->Parameters.DeviceIoControl.IoControlCode;

  if (pIoStackIrp)
  {
    switch (controlCode)
    {
      case IO_READ_REQUEST:
      {
        status = Read((PKERNEL_READ_REQUEST)pIrp->AssociatedIrp.SystemBuffer);
        LOG("Received read control\n");
        break;
      }
      case IO_WRITE_REQUEST:
      {
        status = Write((PKERNEL_WRITE_REQUEST)pIrp->AssociatedIrp.SystemBuffer);
        LOG("Received write control\n");
        break;
      }
      default:
      {
        status = STATUS_INVALID_PARAMETER;
        LOG("Unknown request control\n");
        break;
      }
    }
  }
  else
  {
    status = STATUS_UNSUCCESSFUL;
    LOG("Invalid IRP stack pointer\n");
  }

  pIrp->IoStatus.Status = status;
  pIrp->IoStatus.Information = 0;

  IoCompleteRequest(pIrp, IO_NO_INCREMENT);

  return pIrp->IoStatus.Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
  UNREFERENCED_PARAMETER(pRegPath);

  NTSTATUS status = STATUS_SUCCESS;
  PDEVICE_OBJECT pDeviceObject = NULL;

  // Set driver callbacks
  pDriverObject->DriverUnload = DriverUnload;

  for (ULONG i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    pDriverObject->MajorFunction[i] = EventDefaultHandler;

  pDriverObject->MajorFunction[IRP_MJ_CREATE] = EventCreateClose;
  pDriverObject->MajorFunction[IRP_MJ_CLOSE] = EventCreateClose;
  //pDriverObject->MajorFunction[IRP_MJ_WRITE] = EventWrite;
  pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EventIoControl;

  // Create I/O devices
  RtlInitUnicodeString(&sDeviceName, L"\\Device\\TitanKMD");
  RtlInitUnicodeString(&sWin32Device, L"\\DosDevices\\TitanKMD");

  status = IoCreateDevice(pDriverObject, 0, &sDeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &pDeviceObject);

  if (!NT_SUCCESS(status))
  {
    LOG("IoCreateDevice error\n");
    return status;
  }
  if (!pDeviceObject)
  {
    LOG("Unexpacted I/O error\n");
    return status;
  }

  pDeviceObject->Flags |= DO_DIRECT_IO;
  pDeviceObject->Flags |= DO_BUFFERED_IO;
  pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

  // Create symbolic link
  status = IoCreateSymbolicLink(&sWin32Device, &sDeviceName);

  if (!NT_SUCCESS(status))
  {
    LOG("IoCreateSymbolicLink error\n");
    return status;
  }

  LOG("Symbolic link %.*ws -> %.*ws created\n",
    sWin32Device.Length / sizeof(WCHAR), sWin32Device.Buffer,
    sDeviceName.Length / sizeof(WCHAR), sDeviceName.Buffer
  );

  LOG("Driver loaded\n");

  return status;
}