#include <titan.h>

namespace titan
{
  namespace util
  {
    std::vector<std::uint8_t> int_to_bytes(std::uint64_t val)
    {
      std::vector<std::uint8_t> bytes{};

      for (std::size_t i{}; i < 4; i++)
        bytes.emplace_back((std::uint8_t)(val >> (i * 8)));

      return bytes;
    }
    std::vector<std::uint8_t> str_to_bytes(std::string const& str)
    {
      std::vector<std::uint8_t> bytes{};

      for (std::size_t i{}; i < str.size(); i += 2)
        bytes.emplace_back((std::uint8_t)std::strtoul(str.substr(i, 2).c_str(), nullptr, 16));

      return bytes;
    }

    std::string bytes_to_str(std::vector<std::uint8_t> const& bytes)
    {
      std::string str{};

      str.resize(bytes.size() * 2);

      for (std::size_t i{}; i < bytes.size(); i++)
        std::sprintf(&str[i * 2], "%02X", *(&bytes[i]));

      return str;
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

  namespace kernel
  {
    std::int32_t send()
    {
      //DeviceIoControl(hDriver, IO_READ_REQUEST, &ReadRequest, sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), &Bytes, NULL
      return 0;
    }
}

  namespace system
  {
    std::int32_t find_process(std::string const& name, std::int32_t flags, PROCESSENTRY32& pe32)
    {
      std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv{};

      pe32.dwSize = sizeof(PROCESSENTRY32);

      void* hProcessSnap{ CreateToolhelp32Snapshot(flags, 0) };

      if (!Process32First(hProcessSnap, &pe32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      do
      {
        if (wcscmp(conv.from_bytes(name.c_str()).c_str(), pe32.szExeFile) == 0)
        {
          CloseHandle(hProcessSnap);

          return 1;
        }
      } while (Process32Next(hProcessSnap, &pe32));

      CloseHandle(hProcessSnap);

      return 0;
    }
    std::int32_t find_module(std::string const& name, std::int32_t pid, std::int32_t flags, MODULEENTRY32& me32)
    {
      std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> conv{};

      me32.dwSize = sizeof(MODULEENTRY32);

      void* hProcessSnap{ CreateToolhelp32Snapshot(flags, pid) };

      if (!Module32First(hProcessSnap, &me32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      do
      {
        if (wcscmp(conv.from_bytes(name.c_str()).c_str(), me32.szModule) == 0)
        {
          CloseHandle(hProcessSnap);

          return 1;
        }
      } while (Module32Next(hProcessSnap, &me32));

      CloseHandle(hProcessSnap);

      return 0;
    }

    std::uint32_t dump_processes(std::uint32_t flags)
    {
      PROCESSENTRY32 pe32{};
      pe32.dwSize = sizeof(PROCESSENTRY32);

      void* hProcessSnap{ CreateToolhelp32Snapshot(flags, 0) };

      if (!Process32First(hProcessSnap, &pe32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      std::printf("ProcId ParentId ModId HeapId BasePrio Handles Threads ProcName\n");
      std::printf("--------------------------------------------------------------\n");

      do
      {
        std::printf("%6d %8d %5d %6d %8d %7d %7d %ls\n",
          pe32.th32ProcessID,
          pe32.th32ParentProcessID,
          pe32.th32ModuleID,
          pe32.th32DefaultHeapID,
          pe32.pcPriClassBase,
          pe32.cntUsage,
          pe32.cntThreads,
          std::wstring{ pe32.szExeFile, 32 }.data()
        );
      } while (Process32Next(hProcessSnap, &pe32));

      CloseHandle(hProcessSnap);

      return 0;
    }
    std::uint32_t dump_modules(std::uint32_t pid, std::uint32_t flags)
    {
      MODULEENTRY32 me32{};
      me32.dwSize = sizeof(MODULEENTRY32);

      void* hProcessSnap{ CreateToolhelp32Snapshot(flags, pid) };

      if (!Module32First(hProcessSnap, &me32))
      {
        CloseHandle(hProcessSnap);

        return 0;
      }

      std::printf("ModId BaseAddr           EndAddr            Size       Handles    ProcName\n");
      std::printf("--------------------------------------------------------------------------\n");

      do
      {
        std::printf("%5d 0x%p 0x%p %10d %10d %ls\n",
          me32.th32ModuleID,
          (std::uintptr_t)me32.modBaseAddr,
          (std::uintptr_t)me32.modBaseAddr + me32.modBaseSize,
          me32.modBaseSize,
          me32.GlblcntUsage,
          std::wstring{ me32.szModule, 32 }.data()
        );
      } while (Module32Next(hProcessSnap, &me32));

      CloseHandle(hProcessSnap);

      return 0;
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
    std::int32_t read(std::uintptr_t base, std::size_t size, std::uintptr_t assembly)
    {
      void* p_process{ GetCurrentProcess() };
      unsigned long old_protection{};

      std::uintptr_t page_base{ ROUND_DOWN(base, 0x1000) };
      std::size_t page_size{ ROUND_UP(size, 0x1000) };

      if (VirtualProtectEx(p_process, (void*)page_base, page_size, PAGE_EXECUTE_READWRITE, &old_protection))
      {
        ReadProcessMemory(p_process, (void*)base, (void*)assembly, size, nullptr);

        if (VirtualProtectEx(p_process, (void*)page_base, page_size, old_protection, &old_protection))
          if (FlushInstructionCache(p_process, (void*)page_base, page_size))
            return 1;
      }

      return 0;
    }
    std::int32_t write(std::uintptr_t base, std::size_t size, std::uintptr_t assembly)
    {
      void* p_process{ GetCurrentProcess() };
      unsigned long old_protection{};

      std::uintptr_t page_base{ ROUND_DOWN((void*)base, 0x1000) };
      std::size_t page_size{ ROUND_UP(size, 0x1000) };

      if (VirtualProtectEx(p_process, (void*)page_base, page_size, PAGE_EXECUTE_READWRITE, &old_protection))
      {
        WriteProcessMemory(p_process, (void*)base, (void*)assembly, size, nullptr);

        if (VirtualProtectEx(p_process, (void*)page_base, page_size, old_protection, &old_protection))
          if (FlushInstructionCache(p_process, (void*)page_base, page_size))
            return 1;
      }

      return 0;
    }

    void dump_memory(std::uintptr_t base, std::uintptr_t offset, std::size_t size, std::size_t page_size)
    {
      for (std::uintptr_t i{ base }; i < base + size; i += page_size)
      {
        std::printf("%p ", (void*)i);

        for (std::uint32_t j{}; j < page_size; j++)
        {
          std::uint8_t byte{ *(std::uint8_t*)(offset + i + j) };
          byte = (byte >= 32 && byte < 127) ? byte : '.';
          std::printf("%X ", byte);
        }

        for (std::uint32_t j{}; j < page_size; j++)
        {
          std::uint8_t byte{ *(std::uint8_t*)(offset + i + j) };
          byte = (byte >= 32 && byte < 127) ? byte : '.';
          std::printf("%c", byte);
        }

        std::printf("\n");
      }
    }
  }

  namespace disassembler
  {
    std::uint32_t disassemble()
    {
      std::uint8_t p_bytes[] =
      {
          0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75,
          0x08, 0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F,
          0x88, 0xFC, 0xDA, 0x02, 0x00
      };

#ifdef _WIN64
#if defined(TITAN_ZYDIS)
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
#endif
#if defined(TITAN_CAPSTONE)
      csh handle{};
      cs_insn* p_inst{};

      std::size_t count{};

      if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return -1;

      count = cs_disasm(handle, p_bytes, sizeof(p_bytes), 0x1000, 0, &p_inst);

      if (count > 0)
      {
        for (std::size_t i{}; i < count; i++)
          std::printf("0x%" PRIx64 ":\t%s\t\t%s\n",
            p_inst[i].address,
            p_inst[i].mnemonic,
            p_inst[i].op_str
          );
      }

      cs_close(&handle);
#endif
#endif

      return 0;
    }
  }

  namespace console
  {
    void parse_args(std::int32_t argc, char** argv)
    {

    }
  }

  namespace filesystem
  {
    std::int32_t read_int(std::fstream& stream, std::size_t offset, std::uint32_t big_endian)
    {
      std::int32_t result{};
      std::uint8_t buffer[4]{};

      stream.seekg(offset, std::ios::beg);
      stream.read((char*)&buffer[0], 4);

      result = big_endian
        ? (std::uint8_t)buffer[0] << 24 | (std::uint8_t)buffer[1] << 16 | (std::uint8_t)buffer[2] << 8 | (std::uint8_t)buffer[3]
        : (std::uint8_t)buffer[3] << 24 | (std::uint8_t)buffer[2] << 16 | (std::uint8_t)buffer[1] << 8 | (std::uint8_t)buffer[0];

      return result;
    }
    std::string read_str(std::fstream& stream, std::size_t offset)
    {
      std::string result{};
      char chr{};

      stream.seekg(offset, std::ios::beg);

      while (stream.get(chr))
      {
        if (chr == '\0')
          break;

        result += chr;
      }

      return result;
    }

    namespace ea
    {
      void dump_viv_header(std::string const& file)
      {
        std::fstream stream{};

        stream.open(file.c_str(), std::ios::in | std::ios::binary);

        if (stream.is_open())
        {
          std::int32_t magic{ read_int(stream, 0, 1) };
          std::uint32_t total_file_size{ (std::uint32_t)read_int(stream, 4, 1) };
          std::uint32_t file_count{ (std::uint32_t)read_int(stream, 8, 1) };
          std::uint32_t header_size{ (std::uint32_t)read_int(stream, 12, 1) };

          assert(magic == 0x42494748);
          assert(total_file_size > 0);
          assert(file_count > 0);
          assert(header_size > 0);

          std::printf("File: %s\n", file.c_str());
          std::printf("Total file size: %u\n", total_file_size);
          std::printf("File count: %u\n", file_count);
          std::printf("Header size: %u\n", header_size);

          std::size_t read_position{ 16 };

          for (std::size_t i{}; i < file_count; i++)
          {
            std::uint32_t file_offset{ (std::uint32_t)read_int(stream, read_position, 1) };
            std::uint32_t file_size{ (std::uint32_t)read_int(stream, read_position + 4, 1) };
            std::string file_name{ read_str(stream, read_position + 8) };

            std::printf("%8u 0x%p %16u %16u %s\n", i, (void*)read_position, file_offset, file_size, file_name.c_str());

            read_position += 4;
            read_position += 4;
            read_position += file_name.size();
            read_position += 1;
          }

          std::printf("\n");

          stream.close();
        }
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

    return exit_code;
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
          std::size_t size{ (std::size_t)std::strtoul(tokens[3].data(), nullptr, 10) };
          std::size_t page_size{ (std::size_t)std::strtoul(tokens[4].data(), nullptr, 10) };

          memory::dump_memory(begin, 0, size, page_size);
        }

        if (tokens[1] == "processes")
        {
          system::dump_processes(TH32CS_SNAPPROCESS);
        }

        if (tokens[1] == "modules")
        {
          std::uint32_t pid{ (std::uint32_t)std::atoi(tokens[2].data()) };

          system::dump_modules(pid, TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32);
        }
      }

      if (tokens[0] == "disassemble")
      {
        std::uintptr_t begin{ (std::uintptr_t)std::strtoul(tokens[1].data(), nullptr, 16) };
        std::size_t size{ (std::size_t)std::strtoul(tokens[2].data(), nullptr, 10) };

        disassembler::disassemble();
      }
    }

    return 0;
  }
}