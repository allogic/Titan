#include <titan.h>

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    while (1)
    {
      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {

      }
    }
  }

  return 0;
}

ENTRY_POINT