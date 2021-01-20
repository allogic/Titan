#include <titan.h>

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {    
    MODULEENTRY32 ds3{};

    titan::system::find_module(L"deadspace3.exe", pid, TH32CS_SNAPMODULE, ds3);

    std::uintptr_t ds3_begin{ (std::uintptr_t)ds3.modBaseAddr };
    std::uintptr_t ds3_end{ ds3.modBaseSize };

    //std::uintptr_t ammo{ titan::scanner::find_pattern(ds3_begin, ds3_end, "89 BE 90 02 00 00 FF D0") };
    //std::uintptr_t stasis_counter{ titan::scanner::find_pattern(ds3_begin, ds3_end, "D9 56 08 D9 EE") };

    while (1)
    {
      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {
        static std::uint32_t ammo_hack_active{};
        ammo_hack_active = !ammo_hack_active;
        titan::memory::patch(ds3_begin + 0x1D6F5E, ammo_hack_active ? "90 90 90 90 90 90" : "89 BE 90 02 00 00");
        std::printf("infinit ammo %d\n", ammo_hack_active);
      }

      if (GetAsyncKeyState(VK_F2) & 0x0001)
      {
        static std::uint32_t stasis_hack_active{};
        stasis_hack_active = !stasis_hack_active;
        titan::memory::patch(ds3_begin + 0x181FC6, stasis_hack_active ? "90 90 90" : "D9 56 08");
        std::printf("infinit stasis counter %d\n", stasis_hack_active);
      }
    }
  }

  return 0;
}

ENTRY_POINT