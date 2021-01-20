#include <titan.h>

namespace titan
{
  namespace util
  {
    std::vector<std::uint8_t> hex_to_bytes(std::string const& hex)
    {
      std::vector<std::uint8_t> bytes{};

      for (std::uint32_t i{}; i < hex.size(); i += 2)
        bytes.emplace_back((std::uint8_t)std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16));

      return bytes;
    }
    void replace_string(std::string& subject, std::string const& search, std::string const& replace)
    {
      std::size_t i{};

      while ((i = subject.find(search, i)) != std::string::npos)
      {
        subject.replace(i, search.size(), replace);
        i += replace.size();
      }
    }
    std::vector<std::string> tokenize(std::string subject, std::string const& delimiter)
    {
      std::vector<std::string> tokens{};

      std::size_t i{};

      while ((i = subject.find(delimiter)) != std::string::npos)
      {
        tokens.emplace_back(subject.substr(0, i));
        subject.erase(0, i + delimiter.size());
      }

      tokens.emplace_back(subject);

      return tokens;
    }
  }

  namespace system
  {
    std::int32_t find_process(std::wstring const& name, std::int32_t flags, PROCESSENTRY32& pe32)
    {
      pe32.dwSize = sizeof(PROCESSENTRY32);

      HANDLE hProcessSnap{ CreateToolhelp32Snapshot(flags, 0) };

      if (!Process32First(hProcessSnap, &pe32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      do
      {
        if (wcscmp(name.c_str(), pe32.szExeFile) == 0)
        {
          CloseHandle(hProcessSnap);

          return 1;
        }
      } while (Process32Next(hProcessSnap, &pe32));

      CloseHandle(hProcessSnap);

      return 0;
    }
    std::int32_t find_module(std::wstring const& name, std::int32_t pid, std::int32_t flags, MODULEENTRY32& me32)
    {
      me32.dwSize = sizeof(MODULEENTRY32);

      HANDLE hProcessSnap{ CreateToolhelp32Snapshot(flags, pid) };

      if (!Module32First(hProcessSnap, &me32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      do
      {
        if (wcscmp(name.c_str(), me32.szModule) == 0)
        {
          CloseHandle(hProcessSnap);

          return 1;
        }
      } while (Module32Next(hProcessSnap, &me32));

      CloseHandle(hProcessSnap);

      return 0;
    }

    void dump_processes()
    {

    }
    void dump_modules()
    {

    }
  }

  namespace scanner
  {
    std::uintptr_t find_pattern(std::uintptr_t begin, std::uintptr_t end, std::string const& pattern, std::int32_t result)
    {
      char const* p_pattern{ pattern.c_str() };

      std::int32_t results{};
      std::uintptr_t match{};

      for (std::uintptr_t i{ begin }; i < end; i++)
      {
        if (!*p_pattern)
          return match;

        if (*(std::uint8_t*)p_pattern == '\?' || *(std::uint8_t*)i == GET_BYTE(p_pattern))
        {
          if (!match)
            match = i;

          if (!p_pattern[2])
          {
            if (results + 1 != result)
              results++;
            else
              return match;
          }

          if (*(std::uint8_t*)p_pattern == '\?\?' || *(std::uint8_t*)p_pattern != '\?')
            p_pattern += 3;
          else
            p_pattern += 2;
        }
        else
        {
          p_pattern = pattern.c_str();
          match = 0;
        }
      }

      return begin;
    }
  }

  namespace memory
  {
    std::int32_t patch(std::uintptr_t base, std::string buffer)
    {
      unsigned long old_protection{};

      std::uint32_t size{};

      void* p_addr{ (void*)base };

      std::size_t num_bytes{ std::count(buffer.begin(), buffer.end(), ' ') + (std::size_t)1 };

      util::replace_string(buffer, " ", "");

      std::vector<std::uint8_t> bytes{ util::hex_to_bytes(buffer) };

      base = ROUND_DOWN(p_addr, 0x1000);
      size = ROUND_UP(num_bytes, 0x1000);

      if (VirtualProtect((void*)base, size, PAGE_EXECUTE_READWRITE, &old_protection))
      {
        std::memcpy(p_addr, bytes.data(), num_bytes);

        if (VirtualProtect((void*)base, size, old_protection, &old_protection))
        {
          if (FlushInstructionCache(GetCurrentProcess(), (void*)base, size))
            return 0;

          return GetLastError();
        }
      }

      return GetLastError();
    }

    std::int32_t region_valid(std::uintptr_t base, std::uintptr_t offset)
    {
      return 0;
    }

    std::uint32_t read_int(std::uintptr_t base, std::uintptr_t offset)
    {
      return 0;
    }
    void write_int(std::uintptr_t base, std::uintptr_t offset, std::int32_t value)
    {

    }

    std::string read_string(std::uintptr_t base, std::uintptr_t offset)
    {
      return "";
    }
    void write_string(std::uintptr_t base, std::uintptr_t offset, std::string const& value)
    {

    }

    std::float_t read_float(std::uintptr_t base, std::uintptr_t offset)
    {
      return 0.f;
    }
    void write_float(std::uintptr_t base, std::uintptr_t offset, std::float_t value)
    {

    }

    void dump_memory(std::uintptr_t begin, std::size_t size)
    {
      std::printf("Dumping memory from 0x%X to 0x%X\n", begin, begin + size);
    }
    void dump_memory()
    {

    }
  }

  namespace disassembler
  {
    void disassemble()
    {
      std::uint8_t p_bytes[] =
      {
          0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75,
          0x08, 0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F,
          0x88, 0xFC, 0xDA, 0x02, 0x00
      };

      ZydisDecoder decoder{};
      ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);

      ZydisFormatter formatter{};
      ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

      std::size_t offset{};
      std::size_t size{ sizeof(p_bytes) };

      ZydisDecodedInstruction instruction;

      while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, p_bytes + offset, size - offset, &instruction)))
      {
        char p_buffer[256]{};

        ZydisFormatterFormatInstruction(&formatter, &instruction, p_buffer, sizeof(p_buffer), 0);

        std::printf("%s\n", p_buffer);

        offset += instruction.length;
      }
    }
  }

  std::int32_t inject_dll(std::string const& file, std::int32_t pid)
  {
    unsigned long exit_code{};

    void* p_process{};
    void* p_dll_path_addr{};
    void* p_load_lib_addr{};
    void* p_thread{};

    p_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    p_dll_path_addr = VirtualAllocEx(p_process, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    WriteProcessMemory(p_process, p_dll_path_addr, file.c_str(), file.size(), nullptr);

    p_load_lib_addr = GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA");
    p_thread = CreateRemoteThread(p_process, nullptr, 0, (LPTHREAD_START_ROUTINE)p_load_lib_addr, p_dll_path_addr, 0, nullptr);

    WaitForSingleObject(p_thread, INFINITE);
    GetExitCodeThread(p_thread, &exit_code);

    CloseHandle(p_thread);

    VirtualFreeEx(p_process, p_dll_path_addr, 0, MEM_RELEASE);

    CloseHandle(p_process);

    return !exit_code ? 1 : 0;
  }
  std::int32_t spawn_console(std::uint32_t& pid)
  {
    if (!AllocConsole())
      return 0;

    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);

    pid = GetProcessId(GetCurrentProcess());

    return 1;
  }
  std::int32_t interactive()
  {
    std::string cmd{};
    std::vector<std::string> tokens{};

    while (std::getline(std::cin, cmd))
    {
      tokens = util::tokenize(cmd, " ");

      if (tokens[0] == "dump")
      {
        if (tokens[1] == "memory")
        {
          std::uintptr_t begin{ (std::uintptr_t)std::strtoul(tokens[2].data(), nullptr, 16) };
          std::uintptr_t size{ (std::uintptr_t)std::strtoul(tokens[3].data(), nullptr, 10) };

          memory::dump_memory(begin, size);
        }
      }

      if (tokens[0] == "disassemble")
      {
        std::uintptr_t begin{ (std::uintptr_t)std::strtoul(tokens[1].data(), nullptr, 16) };
        std::uintptr_t size{ (std::uintptr_t)std::strtoul(tokens[2].data(), nullptr, 10) };

        disassembler::disassemble();
      }
    }

    return 0;
  }
}