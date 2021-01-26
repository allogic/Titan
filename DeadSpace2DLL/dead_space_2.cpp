#include <titan.h>

unsigned long __stdcall DllThread(HINSTANCE p_instance)
{
  std::uint32_t pid{};

  if (titan::spawn_console(pid))
  {
    MODULEENTRY32 ds2{};

    titan::system::find_module(L"deadspace2.exe", pid, TH32CS_SNAPMODULE, ds2);

    std::uintptr_t ds2_begin{ (std::uintptr_t)ds2.modBaseAddr };
    std::uintptr_t ds2_end{ ds2.modBaseSize };

    while (1)
    {
      // DBAF57: 89 AE 9C 03 00 00 - mov [esi+39C],ebp - trigger on focus hit
      // DBAEF0: 89 AE 9C 03 00 00 - mov [esi+39C],ebp - trigger on reload

      // aiming
      // DB0DE4:         8B 91 9C 03 00 00 - mov edx,[ecx+39C]
      // DC86A3:         8B 87 9C 03 00 00 - mov eax,[edi+39C]

      // fire
      // 88C407:         2B 82 9C 03 00 00 - sub eax,[edx+39C]
      // 8747A5:         8B B0 9C 03 00 00 - mov esi,[eax+39C]
      // DBAE99:         8B 86 9C 03 00 00 - mov eax,[esi+39C]
      // DB8BE6:         8B 8E 9C 03 00 00 - mov ecx,[esi+39C]
      // DBAF0C:         8B 8E 9C 03 00 00 - mov ecx,[esi+39C]
      // DBAF57:         89 AE 9C 03 00 00 - mov [esi+39C],ebp
      // DBAF79:         8B 86 9C 03 00 00 - mov eax,[esi+39C]
      // 892224:      83 BF 9C 03 00 00 00 - cmp dword ptr [edi+39C],0
      // DBAF5F: C7 86 9C 03 00 00 00 00 00 00 - mov dword ptr [esi+39C],0

      // reload
      // 88C538:         2B BE 9C 03 00 00 - sub edi,[esi+39C]
      // DA7117:         8B 86 9C 03 00 00 - mov eax,[esi+39C]
      // DA7129:         89 86 9C 03 00 00 - mov [esi+39C],eax
      // DA7147:         8B 86 9C 03 00 00 - mov eax,[esi+39C]
      // DBAD45:         8B 8E 9C 03 00 00 - mov ecx,[esi+39C]
      // DBAD94:      83 BE 9C 03 00 00 00 - cmp dword ptr [esi+39C],0
      // DBADBF:         8B 86 9C 03 00 00 - mov eax,[esi+39C]
      // DBAEF0:         89 AE 9C 03 00 00 - mov [esi+39C],ebp

      if (GetAsyncKeyState(VK_F1) & 0x0001)
      {
        static std::uint32_t active{};
        active = !active;

        titan::memory::patch(ds2_begin + 0xDBAF57, active ? "90 90 90 90 90 90" : "89 AE 9C 03 00 00");
        titan::memory::patch(ds2_begin + 0xDBAF5F, active ? "90 90 90 90 90 90 90 90 90 90" : "C7 86 9C 03 00 00 00 00 00 00");

        titan::memory::patch(0xDBAF57, active ? "90 90 90 90 90 90" : "89 AE 9C 03 00 00");
        titan::memory::patch(0xDBAF5F, active ? "90 90 90 90 90 90 90 90 90 90" : "C7 86 9C 03 00 00 00 00 00 00");

        std::printf("infinit ammo %d\n", active);
      }
    }
  }

  return 0;
}

ENTRY_POINT