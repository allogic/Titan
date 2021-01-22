#pragma warning (disable : 4100)

#include <ntddk.h>
#include <wdf.h>

//windbg.exe !process 0 0 explorer.exe
//windbg.exe .process /p 0x?
//windbg.exe .reload /f dxgkrnl.sys

//NtQueryCompositionSurfaceStatistics

//sc.exe create kernel_bypass type=kernel binpath="C:\Users\Michael\source\repos\Titan\x64\Debug\KernelBypass.sys"
//sc.exe start kernel_bypass
//sc.exe stop kernel_bypass

NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT p_driver_object,
  _In_ PUNICODE_STRING p_registry_path);

NTSTATUS UnloadDriver(
  _In_ PDRIVER_OBJECT p_driver_object);

NTSTATUS KmdfKernelBypassEvtDeviceAdd(
  _In_ WDFDRIVER p_driver,
  _Inout_ PWDFDEVICE_INIT p_device_init);

void KmdfKernelBypassEvtDeviceUnload(
  _In_ WDFDRIVER p_driver);

NTSTATUS DriverEntry(
  _In_ PDRIVER_OBJECT p_driver_object,
  _In_ PUNICODE_STRING p_registry_path)
{
  NTSTATUS status = STATUS_SUCCESS;

  p_driver_object->DriverUnload = UnloadDriver;

  DbgPrintEx(0, 0, "Kernel bypass DriverEntry\n");

  WDF_DRIVER_CONFIG config;
  WDF_DRIVER_CONFIG_INIT(&config, KmdfKernelBypassEvtDeviceAdd);
  config.EvtDriverUnload = KmdfKernelBypassEvtDeviceUnload;

  status = WdfDriverCreate(p_driver_object, p_registry_path, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

  return status;
}

NTSTATUS UnloadDriver(
  _In_ PDRIVER_OBJECT p_driver_object)
{
  NTSTATUS status = STATUS_SUCCESS;

  DbgPrintEx(0, 0, "Kernel bypass UnloadDriver\n");

  return status;
}

NTSTATUS KmdfKernelBypassEvtDeviceAdd(
  _In_ WDFDRIVER p_driver,
  _Inout_ PWDFDEVICE_INIT p_device_init)
{
  NTSTATUS status = STATUS_SUCCESS;

  DbgPrintEx(0, 0, "Kernel bypass KmdfKernelBypassEvtDeviceAdd\n");

  WDFDEVICE p_device;

  status = WdfDeviceCreate(&p_device_init, WDF_NO_OBJECT_ATTRIBUTES, &p_device);

  return status;
}

void KmdfKernelBypassEvtDeviceUnload(
  _In_ WDFDRIVER p_driver)
{
  DbgPrintEx(0, 0, "Kernel bypass KmdfKernelBypassEvtDeviceUnload\n");
}