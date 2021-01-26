#include <titan.h>

#ifdef _WIN64
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\x64Debug\\"
#else
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\Debug\\"
#endif

int wmain()
{
  //titan::interactive();

  PROCESSENTRY32 pe32{};

  if (titan::system::find_process(L"deadspace2.exe", TH32CS_SNAPPROCESS, pe32))
  {
    if (titan::inject_dll(PATH "DeadSpace2DLL.dll", pe32.th32ProcessID))
    {
      return 0;
    }
  }

  return -1;
}