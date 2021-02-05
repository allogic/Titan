#include <Titan.h>

int main(int argc, char** argv)
{
  //titan::console::parse_args(argc, argv);

  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile0.viv");
  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile1.viv");
  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile2.viv");
  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile3.viv");
  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile4.viv");
  titan::filesystem::ea::dump_viv_header("C:\\Program Files (x86)\\Origin Games\\Dead Space 3\\bigfile5.viv");
}