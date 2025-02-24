
#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>

#define MAX_COMMON_TX_DATA_SIZE 20480

extern uint8_t common_tx_data_buffer[MAX_COMMON_TX_DATA_SIZE];
void uleb_encode(int num, uint8_t *num_bytes, int *len);

#endif