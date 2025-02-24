// common_tx.c
#include "common_tx.h"

// 定义变量
uint8_t common_tx_data_buffer[MAX_COMMON_TX_DATA_SIZE]
    __attribute__((section(".secMessageSection")));

void uleb_encode(int num, uint8_t *num_bytes, int *len) {
  while (num > 0) {
    num_bytes[*len] = num & 127;
    if (num >>= 7) {
      num_bytes[*len] |= 128;
    }
    *len += 1;
  }
}
