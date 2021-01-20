#include <titan.h>

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    titan::interactive();

    MODULEENTRY32 lol{};

    titan::system::find_module(L"League of Legends.exe", pid, TH32CS_SNAPMODULE, lol);

    std::uintptr_t lol_begin{ (std::uintptr_t)lol.modBaseAddr };
    std::uintptr_t lol_end{ lol.modBaseSize };
  }

  return 0;
}

ENTRY_POINT