#include <titan.h>

static volatile void hook_weapon_module()
{
  std::exit(42);
}

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    MODULEENTRY32 ds3{};
    MODULEENTRY32 ds3_dll{};

    titan::system::find_module(L"deadspace3.exe", pid, TH32CS_SNAPMODULE, ds3);
    titan::system::find_module(L"DeadSpace3DLL.dll", pid, TH32CS_SNAPMODULE, ds3_dll);

    std::uintptr_t ds3_begin{ (std::uintptr_t)ds3.modBaseAddr };
    std::uintptr_t ds3_end{ ds3.modBaseSize };

    std::uintptr_t ds3_dll_begin{ (std::uintptr_t)ds3_dll.modBaseAddr };
    std::uintptr_t ds3_dll_end{ ds3_dll.modBaseSize };

    while (1)
    {
      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(ds3_begin + 0x1D6F5E, active ? "90 90 90 90 90 90" : "89 BE 90 02 00 00");

        std::printf("infinit ammo %d\n", active);
      }

      if (GetAsyncKeyState(VK_F2) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(ds3_begin + 0x181FC6, active ? "90 90 90" : "D9 56 08");

        std::printf("infinit stasis counter %d\n", active);
      }

      if (GetAsyncKeyState(VK_F3) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(ds3_begin + 0xD1118, active ? "90 90 90" : "D9 57 04");
        titan::memory::patch(ds3_begin + 0xD1181, active ? "90 90 90" : "D9 5F 04");

        std::printf("attack speed %d\n", active);
      }

      if (GetAsyncKeyState(VK_F4) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(ds3_begin + 0xDC400, active ? "90 90 90" : "D9 5F 18");

        std::printf("reload speed %d\n", active);
      }

      if (GetAsyncKeyState(VK_F5) & 0x0001)
      {
        static std::uint32_t initialized{};
        static std::uint32_t active{};
        static std::uintptr_t hook_addr{};

        if (!initialized)
        {
          initialized = !initialized;

          std::printf("ds3_begin %p\n", (void*)ds3_begin);

          // D9 80 - Push ST(i) onto the FPU register stack.
          hook_addr = titan::memory::gate(ds3_begin + 0xD117E, R"asm(
            90 90 90 90 90 90
          )asm");
        }

        active = !active;

        // 0xE1040 - E8 BB00FFFF  - call deadspace3.exe+D1100

        std::vector<std::uint8_t> hook_addr_bytes{ titan::util::int_to_bytes(hook_addr) };
        std::string hook_addr_bytes_str{ titan::util::bytes_reverse(titan::util::bytes_to_str(hook_addr_bytes)) };

        std::string hook_bytes    { "BA FF FF FF FF 90 FF E2 90" };
        std::string original_bytes{ "D9 80 D4 02 00 00 D8 47 04" };

        titan::memory::patch(ds3_begin + 0xD1178, active ? hook_bytes : original_bytes);
        titan::memory::patch(ds3_begin + 0xD1178 + 1, hook_addr_bytes_str);

        std::printf("module hook %d\n", active);
      }
    }
  }

  return 0;
}

ENTRY_POINT