#include <titan.h>

int main(int argc, char** argv)
{
  PROCESSENTRY32 pe32{};

  std::int32_t injected{};
  std::int32_t process_found{};

  std::string process_name{ argv[1] };
  std::string dll_name{ argv[2] };

  while (1)
  {
    process_found = titan::system::find_process(process_name, TH32CS_SNAPPROCESS, pe32);

    if (injected)
    {
      if (!process_found)
        injected = 0;
    }
    else
    {
      std::printf("Waiting...\n");

      if (process_found)
      {
        titan::inject_dll(dll_name, pe32.th32ProcessID);

        injected = 1;

        std::printf("Injecting...\n");
      }
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  }

  return 0;
}