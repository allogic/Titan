#include <titan.h>

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

PIMAGE_NT_HEADERS get_headers(PBYTE base)
{
  PIMAGE_DOS_HEADER p_dos_header{ (PIMAGE_DOS_HEADER)base };

  return (PIMAGE_NT_HEADERS)base + p_dos_header->e_lfanew;
}

PIMAGE_SECTION_HEADER find_rdata_section(PBYTE base)
{
  PIMAGE_NT_HEADERS p_nt_header{ get_headers(base) };
  PIMAGE_SECTION_HEADER p_section_header{ IMAGE_FIRST_SECTION(p_nt_header) };

  for (std::size_t i{}; i < p_nt_header->FileHeader.NumberOfSections; i++)
  {
    if (std::strcmp(".rdata", (char*)p_section_header[i].Name) == 0)
    {
      return &p_section_header[i];
    }
  }

  return nullptr;
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
        PBYTE base{ (PBYTE)GetModuleHandle(nullptr) };

        PIMAGE_NT_HEADERS p_nt_headers{ get_headers(base) };
        PIMAGE_LOAD_CONFIG_DIRECTORY p_load_config_dir{ (PIMAGE_LOAD_CONFIG_DIRECTORY)(base + p_nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress) };

        std::printf("%d\n", p_load_config_dir->GlobalFlagsSet);
      }
    }
  }

  return 0;
}

ENTRY_POINT