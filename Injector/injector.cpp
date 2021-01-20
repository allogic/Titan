#include <titan.h>

int wmain()
{
  PROCESSENTRY32 pe32{};

  if (titan::system::find_process(L"r5apex.exe", TH32CS_SNAPPROCESS, pe32))
  {
    if (titan::inject_dll("C:\\Users\\Michael\\source\\repos\\Titan\\x64\\Debug\\ApexLegendsDLL.dll", pe32.th32ProcessID))
    {
      return 0;
    }
  }

  return -1;
}