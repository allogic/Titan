#pragma once

#pragma warning (disable : 6387 6031)

#include <windows.h>
#include <tlhelp32.h>

#include <iostream>
#include <cstdint>
#include <string>
#include <cstring>
#include <vector>

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
  std::int32_t inject_dll(std::string const& file, std::int32_t pid);
  std::int32_t spawn_console(std::uint32_t& pid);

  namespace util
  {
    std::vector<std::uint8_t> hex_to_bytes(std::string const& hex);
    void replace_string(std::string& subject, std::string const& search, std::string const& replace);
  }

  namespace system
  {
    std::int32_t find_process(std::wstring const& name, std::int32_t flags, PROCESSENTRY32& pe32);
    std::int32_t find_module(std::wstring const& name, std::int32_t pid, std::int32_t flags, MODULEENTRY32& me32);
  }

  namespace scanner
  {
    std::uintptr_t find_pattern(std::uintptr_t begin, std::uintptr_t end, std::string const& pattern, std::int32_t result = 1);
  }

  namespace memory
  {
    std::int32_t __stdcall patch(std::uintptr_t base, std::string buffer);

    std::int32_t region_valid(std::uintptr_t base, std::uintptr_t offset);

    std::uint32_t read_int(std::uintptr_t base, std::uintptr_t offset);
    void write_int(std::uintptr_t base, std::uintptr_t offset, std::int32_t value);

    std::string read_string(std::uintptr_t base, std::uintptr_t offset);
    void write_string(std::uintptr_t base, std::uintptr_t offset, std::string const& value);

    std::float_t read_float(std::uintptr_t base, std::uintptr_t offset);
    void write_float(std::uintptr_t base, std::uintptr_t offset, std::float_t value);
  }
}