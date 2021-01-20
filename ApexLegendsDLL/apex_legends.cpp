#include <titan.h>

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    MODULEENTRY32 ds3{};

    titan::system::find_module(L"r5apex.exe", pid, TH32CS_SNAPMODULE, ds3);

    std::uintptr_t ds3_begin{ (std::uintptr_t)ds3.modBaseAddr };
    std::uintptr_t ds3_end{ ds3.modBaseSize };

    while (1)
    {
      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {
        std::printf("so far so good\n");
      }
    }
  }

  return 0;
}

ENTRY_POINT