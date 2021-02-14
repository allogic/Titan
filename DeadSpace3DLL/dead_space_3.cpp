#include <titan.h>

__declspec(naked) void weapon_mod_original()
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
    //mov edx, 0x41200000         // 5 - Mov reload speed into edx
    //mov [edi + 0x18], edx       // 3 - Mov reload speed into memory
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
    nop                         // 1
  }
}

void signal_handler(std::int32_t signal)
{
  std::printf("interrupt received %d\n", signal);

  titan::memory::write(0x400000 + 0xD116E, 6, (std::uintptr_t)"\xD9\x80\xD8\x02\x00\x00");

  void(*jmp)() = (void(*)())0x4D116E;
  jmp();
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

        titan::memory::write(0x400000 + 0x1D6F5E, 6, (std::uintptr_t)(active ? "\x90\x90\x90\x90\x90\x90" : "\x89\xBE\x90\x02\x00\x00"));

        std::printf("infinit ammo %d\n", active);
      }
      if (GetAsyncKeyState(VK_F2) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::write(0x400000 + 0x181FC6, 3, (std::uintptr_t)(active ? "\x90\x90\x90" : "\xD9\x56\x08"));

        std::printf("infinit stasis counter %d\n", active);
      }
      if (GetAsyncKeyState(VK_F3) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::write(0x400000 + 0xD116E, 22, (std::uintptr_t)(active ? weapon_mod_patch : weapon_mod_original));

        //write(0x400000 + 0xDC3FD, 6, active ? (std::uintptr_t)"\x90\x90\x90\x90\x90\x90" : (std::uintptr_t)"\xD9\x45\xFC\xD9\x5F\x18");
        //write(0x400000 + 0x7E5603, 2, active ? (std::uintptr_t)"\x90\x90" : (std::uintptr_t)"\x88\x02");

        std::printf("weapon mods %d\n", active);
      }
      if (GetAsyncKeyState(VK_F5) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        // 0x0046BAB0 entry entity loop

        // deadspace3.EARS::RegisterEntityClasses + 9E2D 1x  -> 0x0046BD6D
        // deadspace3.EARS::RegisterEntityClasses + 9B70 inf -> 0x0046BAB0

        // function call
        // deadspace3.exe+732255 - 51                    - push ecx
        // deadspace3.exe+732256 - 8B CE                 - mov ecx,esi
        // deadspace3.exe+732258 - FF D2                 - call edx

        // dynamic dispatch shit.. player entity

        // EDX -> function body interactable entity
        // args: ECX -> entity ptr
        // deadspace3.EARS::RegisterEntityClasses+9E2B - 8B CE                 - mov ecx,esi
        // deadspace3.EARS::RegisterEntityClasses+9E2D - E8 4E49FDFF           - call deadspace3.exe+406C0

        //titan::memory::write(0x400000 + 0x731F00, 0, (std::uintptr_t)""); // event trigger E register monster entity
        //titan::memory::write(0x400000 + 0x696360, 0, (std::uintptr_t)""); // event trigger E register monster entity
        //titan::memory::write(0x400000 + 0x732180, 0, (std::uintptr_t)""); // event trigger E register monster entity

        std::printf("weapon mods %d\n", active);
      }
      if (GetAsyncKeyState(VK_F6) & 0x0001)
      {
        titan::memory::write(0x400000 + 0xD116E, 6, (std::uintptr_t)"\xCC\x90\x90\x90\x90\x90");

        std::signal(SIGINT, signal_handler);

        std::printf("patched breakpoint\n");
      }
    }
  }

  return 0;
}

ENTRY_POINT