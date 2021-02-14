#include <titan.h>

extern "C" void original();
extern "C" void patch();

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
        
        //titan::memory::write(0x400000 + 0xD116E, active ? (std::uintptr_t)patch : (std::uintptr_t)original);

        //titan::memory::write(0x7FF76C680000 + 0x778A93, 3, active ? (std::uintptr_t)"\x90\x90\x90" : (std::uintptr_t)"\x29\x7B\x54");
        //titan::memory::write(0x7FF76C680000 + 0x7A3905, 3, active ? (std::uintptr_t)"\x90\x90\x90" : (std::uintptr_t)"\x89\x58\x54");
        //titan::memory::write(0x7FF660783A6C, 6, active ? (std::uintptr_t)"\x90\x90\x90\x90\x90\x90" : (std::uintptr_t)"\x88\x87\xB4\x0B\x00\x00");

        titan::memory::write(0x7FF6607B1206, 6, active ? (std::uintptr_t)"\x90\x90\x90\x90\x90\x90" : (std::uintptr_t)"\x88\x83\xB4\x0B\x00\x00");
        titan::memory::write(0x7FF675631206, 6, active ? (std::uintptr_t)"\x90\x90\x90\x90\x90\x90" : (std::uintptr_t)"\x88\x83\xB4\x0B\x00\x00");

        std::printf("infinit spells %d\n", active);
      }
    }
  }

  return 0;
}

ENTRY_POINT