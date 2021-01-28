#include <titan.h>

std::int32_t write(std::uintptr_t base, std::size_t size, std::uintptr_t assembly)
{
  unsigned long old_protection{};

  std::uintptr_t page_base{ ROUND_DOWN((void*)base, 0x1000) };
  std::size_t page_size{ ROUND_UP(size, 0x1000) };

  if (VirtualProtect((void*)page_base, page_size, PAGE_EXECUTE_READWRITE, &old_protection))
  {
    std::memcpy((void*)base, (void*)assembly, size);

    if (VirtualProtect((void*)page_base, page_size, old_protection, &old_protection))
      if (FlushInstructionCache(GetCurrentProcess(), (void*)page_base, page_size))
        return 1;
  }

  return 0;
}

__declspec(naked) void weapon_mod_orig()
{
  __asm
  {
    fld dword ptr [eax + 0x2D8] // 6
    fadd dword ptr [edi]        // 2
    fstp dword ptr [edi]        // 2
    fld dword ptr [eax + 0x2D4] // 6
    fadd dword ptr [edi + 0x4]  // 3
    fstp dword ptr [edi + 0x4]  // 3
  }
}
__declspec(naked) void weapon_mod_patch()
{
  __asm
  {
    mov edx, 0xC479C000         // 5 - Mov attack speed into edx
    mov [edi], edx              // 2 - Mov attack speed higher into memory
    mov [edi + 0x4], edx        // 3 - Mov attack speed lower into memory

    mov edx, 0x41200000         // 5 - Mov reload speed into edx
    mov [edi + 0x18], edx       // 3 - Mov reload speed into memory

    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
  }
}

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    while (1)
    {
      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(0x400000 + 0x1D6F5E, active ? "90 90 90 90 90 90" : "89 BE 90 02 00 00");

        std::printf("infinit ammo %d\n", active);
      }
      if (GetAsyncKeyState(VK_F2) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(0x400000 + 0x181FC6, active ? "90 90 90" : "D9 56 08");

        std::printf("infinit stasis counter %d\n", active);
      }
      if (GetAsyncKeyState(VK_F3) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(0x400000 + 0xD1118, active ? "90 90 90" : "D9 57 04");
        titan::memory::patch(0x400000 + 0xD1181, active ? "90 90 90" : "D9 5F 04");

        std::printf("attack speed %d\n", active);
      }
      if (GetAsyncKeyState(VK_F4) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(0x400000 + 0xDC400, active ? "90 90 90" : "D9 5F 18");

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

          // D9 80 - Push ST(i) onto the FPU register stack.
          hook_addr = titan::memory::inject(0x400000, 0xD117E, R"asm(
            90 90 90 90 90 90
          )asm");
        }

        active = !active;

        // 0xE1040 - E8 BB00FFFF  - call deadspace3.exe+D1100

        std::vector<std::uint8_t> hook_addr_bytes{ titan::util::int_to_bytes(hook_addr) };
        std::string hook_addr_bytes_str{ titan::util::bytes_to_str(hook_addr_bytes) };

        std::string hook_bytes    { "BA " + hook_addr_bytes_str + " 90 FF E2 90" };
        std::string original_bytes{ "D9 80 D4 02 00 00 D8 47 04" };

        titan::memory::patch(0x400000 + 0xD1178, active ? hook_bytes : original_bytes);
        //titan::memory::patch(0x400000 + 0xD1178 + 1, hook_addr_bytes_str);

        std::printf("module hook %d\n", active);
      }
      if (GetAsyncKeyState(VK_F6) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        write(0x400000 + 0xD116E, 22, active ? (std::uintptr_t)weapon_mod_patch : (std::uintptr_t)weapon_mod_orig);

        //write(0x400000 + 0xDC3FD, 6, active ? (std::uintptr_t)"\x90\x90\x90\x90\x90\x90" : (std::uintptr_t)"\xD9\x45\xFC\xD9\x5F\x18");
        //write(0x400000 + 0x7E5603, 2, active ? (std::uintptr_t)"\x90\x90" : (std::uintptr_t)"\x88\x02");

        std::printf("weapon mods %d\n", active);
      }
    }
  }

  return 0;
}

ENTRY_POINT