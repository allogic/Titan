#include <titan.h>

int wmain()
{
  titan::interactive();

  PROCESSENTRY32 pe32{};

  if (titan::system::find_process(L"League of Legends.exe", TH32CS_SNAPPROCESS, pe32))
  {
    if (titan::inject_dll("C:\\Users\\Michael\\Downloads\\Titan\\Debug\\LeagueOfLegendsDLL.dll", pe32.th32ProcessID))
    {
      return 0;
    }
  }

  return -1;
}