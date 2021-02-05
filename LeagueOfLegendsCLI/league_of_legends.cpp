#include <iostream>
#include <map>
#include <vector>
#include <algorithm>

#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

// datatype for read request
typedef struct _KERNEL_READ_REQUEST
{
  ULONG CSGO;

  ULONG LSASS;
  ULONG CSRSS;
  ULONG CSRSS2;
  ULONG UsermodeProgram;
  ULONG TerminatePrograms;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

// database for unload details
typedef struct _KERNEL_UNLOADDRIVER
{
  ULONG UnloadDriver;

} KERNEL_UNLOADDRIVER, * PKERNEL_UNLOADDRIVER;

// Request to write to kernel mode
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_UNLOADDRIVER_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

HANDLE hDriver;

bool SendProcessIDs(ULONG CSGO, ULONG LSASS, ULONG CSRSS, ULONG CSRSS2, ULONG USERMODEANTICHEAT, ULONG TerminatePrograms)
{
  if (hDriver == INVALID_HANDLE_VALUE)
    return false;

  DWORD Return, Bytes;
  KERNEL_READ_REQUEST ReadRequest;

  ReadRequest.CSGO = CSGO;
  ReadRequest.LSASS = LSASS;
  ReadRequest.CSRSS = CSRSS;
  ReadRequest.CSRSS2 = CSRSS2;
  ReadRequest.UsermodeProgram = USERMODEANTICHEAT;
  ReadRequest.TerminatePrograms = TerminatePrograms;

  // send code to our driver with the arguments
  if (DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), &Bytes, NULL))
  {
    return true;
  }
  else
  {
    return false;
  }
}

// These structures are copied from Process Hacker source code (ntldr.h)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

vector<DWORD> GetPIDs(wstring targetProcessName)
{
  vector<DWORD> pids;
  if (targetProcessName == L"")
    return pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32W entry;
  entry.dwSize = sizeof entry;
  if (!Process32FirstW(snap, &entry))
    return pids;
  do {
    if (wstring(entry.szExeFile) == targetProcessName) {
      pids.emplace_back(entry.th32ProcessID);
    }
  } while (Process32NextW(snap, &entry));
  return pids;
}




int main(int argc, char* argv[])
{
  //SetDebugPrivA();


  HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
  //ProtectProcess(hProc);
  SetPriorityClass(hProc, ABOVE_NORMAL_PRIORITY_CLASS);
  CloseHandle(hProc);

  HANDLE hDevice;
  DWORD dwReturn;
  DWORD ProcessId, write;

  hDriver = CreateFileA("\\\\.\\HandleDriver", GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

  DWORD csrss1 = NULL;
  DWORD csrss2 = NULL;
  wstring we1 = L"";
  wstring lsassNoStr1 = we1 + L'c' + L's' + L'r' + L's' + L's' + L'.' + L'e' + L'x' + L'e';
  vector<DWORD> pidsLsass1 = GetPIDs(lsassNoStr1);
  if (pidsLsass1.empty())
    cout << "Not Found" << endl;
  sort(pidsLsass1.begin(), pidsLsass1.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
  csrss1 = pidsLsass1[0];
  csrss2 = pidsLsass1[1];
  if (!csrss1)
    cout << "Not Found" << endl;
  if (!csrss2)
    cout << "Not Found" << endl;

  DWORD pivotPID = NULL;
  wstring we = L"";
  wstring lsassNoStr = we + L'l' + L's' + L'a' + L's' + L's' + L'.' + L'e' + L'x' + L'e';
  vector<DWORD> pidsLsass = GetPIDs(lsassNoStr);
  if (pidsLsass.empty())
    cout << "Not Found" << endl;
  sort(pidsLsass.begin(), pidsLsass.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
  pivotPID = pidsLsass[0];
  if (!pivotPID)
    cout << "Not Found" << endl;


  ULONG pid{ 6352 };
  if (SendProcessIDs(pid, pivotPID, csrss1, csrss2, (ULONG)GetCurrentProcessId(), 1)) // 396 & = Csrss's PIDs
  {
    cout << "Sent Data" << endl;
  }
  else
  {
    cout << "False" << endl;
  }


  CloseHandle(hDriver);
  return 0;
}