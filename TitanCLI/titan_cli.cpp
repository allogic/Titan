#include <Titan.h>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

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

int main(int argc, char** argv)
{
  DWORD written{};
  HANDLE pDevice{};

  // Optain device handle
  pDevice = CreateFileA("\\\\.\\TitanKMD", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

  std::printf("Device: %p\n", pDevice);

  // Write request
  if (pDevice)
  {
    KERNEL_READ_REQUEST readRequest{};
    readRequest.pid = (DWORD)std::atol(argv[1]);
    readRequest.base = 0x666;
    readRequest.size = 666;

    if (DeviceIoControl(pDevice, IO_READ_REQUEST, &readRequest, sizeof(KERNEL_READ_REQUEST), &readRequest, sizeof(KERNEL_READ_REQUEST), &written, NULL))
    {
      std::printf("Read request sent\n");
    }

    // Close device handle
    CloseHandle(pDevice);
  }

  return 0;
}