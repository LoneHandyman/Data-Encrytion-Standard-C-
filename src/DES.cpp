#include "DES.hpp"
#include <algorithm>

unsigned char* DES::encrypt(unsigned char in[], unsigned int inLen, unsigned long long key){
  unsigned long long* sub_keys = splitSubKeys(key);
  return feistelRoundsByBlocks(in, inLen, sub_keys);
}

unsigned char* DES::decrypt(unsigned char in[], unsigned int inLen, unsigned long long key){
  unsigned long long* sub_keys = splitSubKeys(key);
  std::reverse(sub_keys, sub_keys + 16);
  return feistelRoundsByBlocks(in, inLen, sub_keys);
}

unsigned char* DES::feistelRoundsByBlocks(unsigned char in[], unsigned int inLen, unsigned long long* sub_keys){
  if(inLen % DES_BLOCK_LENGHT != 0)
    return 0;
  unsigned char* out = new unsigned char[inLen];
  for (unsigned int i = 0; i < inLen; i += DES_BLOCK_LENGHT) {
    unsigned long long block_bits = 0, inv_ip;
    for (unsigned int j = 0; j < DES_BLOCK_LENGHT; ++j){
      block_bits <<= 8;
      block_bits |= in[j + i];
    }
    unsigned long long ip = swapBits(block_bits, 64, IP, 64);
    unsigned int l = (ip >> 32);
    unsigned int r = (ip & 0xffffffff);

    for (unsigned int j = 0; j < 16; ++j){
      unsigned int l_i = l;
      l = r;
      r = l_i ^ feistel(r, sub_keys[j]);
    }
    inv_ip = swapBits(((((unsigned long long)r) << 32) | ((unsigned long long)l)), 64, INV_IP, 64);
    for (unsigned int j = 0; j < DES_BLOCK_LENGHT; ++j){
      out[j + i] = ((inv_ip >> (8 * (DES_BLOCK_LENGHT - 1 - j))) & 0xff);
    }
  }
  delete[] sub_keys;
  return out;
}

unsigned int DES::feistel(unsigned int r, unsigned long long k){
  unsigned long long e = swapBits(r, 32, EXP, 48);
  unsigned long long e_xor_k = e ^ k;
  unsigned int cat_8blocks = 0;
  for (unsigned int i = 0; i < 8; ++i){
    unsigned char bit6_block = ((e_xor_k >> (6 * (7 - i))) & 0x3f);
    unsigned char row_pos = (((bit6_block >> 4) & 0x2) | (bit6_block & 0x1));
    unsigned char col_pos = ((bit6_block >> 1) & 0xf);
    cat_8blocks <<= 4;
    cat_8blocks |= S_BOX[i][col_pos + 16 * row_pos];
  }
  return swapBits(cat_8blocks, 32, PS_BOX, 32);
}

unsigned int DES::cyclicLeftRotation_28bits(unsigned int n, int d){
  return (0x0fffffff & (n << d)) | ((d | 1) & (n >> (28 - d)));
}

unsigned long long DES::swapBits(unsigned long long n, unsigned int n_bit_size, const unsigned char* LUT_PTR, unsigned int lut_bit_size){
  unsigned long long m = 0;
  for (unsigned int i = 0; i < lut_bit_size; ++i){
    m <<= 1;
    m |= (n >> (n_bit_size - LUT_PTR[i])) & 1;
  }
  return m;
}

unsigned long long* DES::splitSubKeys(unsigned long long key){
  unsigned long long pc_1 = swapBits(key, 64, PC_1, 56);

  unsigned int c0 = (pc_1 >> 28);
  unsigned int d0 = (pc_1 & 0xfffffff);

  unsigned long long* sub_keys = new unsigned long long [16];
  for (unsigned int i = 0; i < 16; ++i){
    c0 = cyclicLeftRotation_28bits(c0, LS[i]);
    d0 = cyclicLeftRotation_28bits(d0, LS[i]);
    sub_keys[i] = swapBits((((unsigned long long)c0) << 28) | ((unsigned long long)d0), 56, PC_2, 48);
  }
  return sub_keys;
}
