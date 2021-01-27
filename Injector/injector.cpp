#include <titan.h>

#ifdef _DEBUG
#ifdef _WIN64
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\x64\\Debug\\"
#else
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\Debug\\"
#endif
#else
#ifdef _WIN64
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\x64\\Release\\"
#else
#define PATH "C:\\Users\\Michael\\Downloads\\Titan\\Release\\"
#endif
#endif

int main()
{
  //titan::interactive();

  PROCESSENTRY32 pe32{};

  if (titan::system::find_process(L"deadspace3.exe", TH32CS_SNAPPROCESS, pe32))
  {
    if (titan::inject_dll(PATH "DeadSpace3DLL.dll", pe32.th32ProcessID))
    {
      return 0;
    }
  }

  return -1;
}