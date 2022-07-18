#include "DES.hpp"
#include <bitset>
#include <string>

int main(){
  DES demo;
  //{0x45,0x4A,0x45,0x4D,0x50,0x4C,0x4F,0x4D};
  unsigned char input[] = "Hola me llamo jose luis";
  unsigned char* out = demo.encrypt(input, 24, 1311768467463790321);
  for (unsigned int i = 0; i < 24; ++i){
    std::cout << out[i];
  }std::cout << std::endl;

  unsigned char* out_2 = demo.decrypt(out, 24, 1311768467463790321);
  for (unsigned int i = 0; i < 24; ++i){
    std::cout << out_2[i];
  }std::cout << std::endl;
  delete[] out;
  delete[] out_2;
  return 0;
}
