#pragma once

#pragma warning (disable : 6387 6031 4477)

#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <cstdint>
#include <string>
#include <cstring>
#include <vector>
#include <sstream>

#include <Zydis/Zydis.h>

#include <capstone/capstone.h>

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (IN_RANGE(x, '0', '9') ? x - '0' : 0))
#define GET_BYTE(x) (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))

#define ROUND_UP(p, align) (((std::size_t)(p) + (align)-1) & ~((align)-1))
#define ROUND_DOWN(p, align) ((std::size_t)(p) & ~((align)-1))

#define ENTRY_POINT                                                                                 \
int __stdcall DllMain(HINSTANCE p_instance, unsigned long reason, void* p_reserved)                 \
{                                                                                                   \
  if (reason == DLL_PROCESS_ATTACH)                                                                 \
  {                                                                                                 \
    void* p_thread{};                                                                               \
                                                                                                    \
    p_thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)DllThread, p_instance, 0, nullptr); \
                                                                                                    \
    if (p_thread)                                                                                   \
    {                                                                                               \
      CloseHandle(p_thread);                                                                        \
    }                                                                                               \
  }                                                                                                 \
                                                                                                    \
  return 1;                                                                                         \
}

namespace titan
{
  namespace util
  {
    std::vector<std::uint8_t> int_to_bytes(std::uint64_t val);
    std::vector<std::uint8_t> str_to_bytes(std::string const& str);

    std::string bytes_to_str(std::vector<std::uint8_t> const& bytes);
    std::string bytes_reverse(std::string const& subject);

    void replace_string(std::string& subject, std::string const& search, std::string const& replace);
    std::vector<std::string> tokenize(std::string subject, std::string const& delimiter);
  }

  namespace system
  {
    std::int32_t find_process(std::wstring const& name, std::int32_t flags, PROCESSENTRY32& pe32);
    std::int32_t find_module(std::wstring const& name, std::int32_t pid, std::int32_t flags, MODULEENTRY32& me32);

    void* get_procedure(std::string const& file_name, std::string const& proc_name);

    std::uint32_t dump_processes(std::uint32_t flags);
    std::uint32_t dump_modules(std::uint32_t pid, std::uint32_t flags);
  }

  namespace scanner
  {
    std::uintptr_t find_pattern(std::uintptr_t begin, std::uintptr_t end, std::string const& pattern, std::int32_t result = 1);
  }

  namespace memory
  {
    std::int32_t patch(std::uintptr_t base, std::string buffer);
    std::int32_t patch(std::uintptr_t base, std::vector<std::uint8_t> bytes);

    std::uintptr_t gate(std::uintptr_t return_addr, std::string buffer);

    std::int32_t read_int(std::uintptr_t base, std::uintptr_t offset);
    std::string read_string(std::uintptr_t base, std::uintptr_t offset);
    std::float_t read_float(std::uintptr_t base, std::uintptr_t offset);

    void write_int(std::uintptr_t base, std::uintptr_t offset, std::int32_t value);
    void write_string(std::uintptr_t base, std::uintptr_t offset, std::string const& value);
    void write_float(std::uintptr_t base, std::uintptr_t offset, std::float_t value);

    void dump_memory(std::uintptr_t base, std::uintptr_t offset, std::size_t size, std::size_t page_size);
  }

  namespace disassembler
  {
    std::uint32_t disassemble();
  }

  std::int32_t inject_dll(std::string const& file, std::int32_t pid);
  std::int32_t spawn_console(std::uint32_t& pid);
  std::int32_t interactive();
}