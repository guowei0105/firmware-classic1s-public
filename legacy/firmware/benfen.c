#include "benfen.h"
#include <inttypes.h>
#include "SEGGER_RTT.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "rtt_log.h"
#include "util.h"

static bool benfen_signing = false;
static uint32_t data_total, data_left;
static uint8_t pubkey[32];
static BLAKE2B_CTX hash_ctx = {0};
static BenfenTxRequest msg_tx_request;
static CONFIDENTIAL HDNode node_cache;
static size_t global_data_chunk_size = 0;

void benfen_get_address_from_public_key(const uint8_t* public_key,
                                        char* address) {
  char hex_addr[67] = {0};
  uint8_t buf[32] = {0};
  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 32);
  blake2b_Update(&ctx, (const uint8_t*)"\x00", 1);
  blake2b_Update(&ctx, public_key, 32);
  blake2b_Final(&ctx, buf, 32);
  hex_addr[0] = '0';
  hex_addr[1] = 'x';
  data2hexaddr((const uint8_t*)buf, 32, hex_addr + 2);
  convert_to_bfc_address(hex_addr, address, BFC_ADDR_SIZE);
}

void convert_to_bfc_address(const char* hex_addr, char* bfc_addr,
                            size_t bfc_addr_size) {
  if (bfc_addr_size < BFC_ADDR_SIZE) {
    return;
  }
  memset(bfc_addr, 0, bfc_addr_size);
  if (strlen(hex_addr) < 3 || hex_addr[0] != '0' ||
      (hex_addr[1] != 'x' && hex_addr[1] != 'X')) {
    return;
  }

  const char* hex_part = hex_addr + 2;
  size_t hex_len = strlen(hex_part);

  if (hex_len == 0 || hex_len > BFC_HEX_LEN) {
    return;
  }

  char padded_hex[BFC_HEX_LEN + 1] = {0};
  size_t padding = BFC_HEX_LEN - hex_len;
  if (padding > 0) {
    memset(padded_hex, '0', padding);
    memcpy(padded_hex + padding, hex_part, hex_len);
  } else {
    memcpy(padded_hex, hex_part, BFC_HEX_LEN);
  }

  SHA256_CTX ctx;
  uint8_t hash[SHA256_DIGEST_LENGTH];
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t*)padded_hex, BFC_HEX_LEN);
  sha256_Final(&ctx, hash);
  memcpy(bfc_addr, BFC_PREFIX, BFC_PREFIX_LEN);
  memcpy(bfc_addr + BFC_PREFIX_LEN, padded_hex, BFC_HEX_LEN);
  char checksum[5] = {0};
  sprintf(checksum, "%02x%02x", hash[0], hash[1]);
  memcpy(bfc_addr + BFC_PREFIX_LEN + BFC_HEX_LEN, checksum, BFC_CHECKSUM_LEN);
  bfc_addr[BFC_ADDR_LENGTH] = '\0';
}

static void handle_signature(const uint8_t* digest, const HDNode* node,
                             BenfenSignedTx* resp) {
#if EMULATOR
  ed25519_sign(digest, 32, node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, digest, 32, 0, resp->signature.bytes, NULL, NULL);
#endif
  memcpy(resp->public_key.bytes, node->public_key + 1, 32);
  resp->signature.size = 64;
  resp->public_key.size = 32;
}

static bool handle_hash(const uint8_t* data, size_t size, uint8_t* digest) {
  if ((data[0] != 0x00) && ((data[1] != 0x00)) && ((data[2] != 0x00))) {
    return false;
  }
  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 32);
  blake2b_Update(&ctx, data, size);
  blake2b_Final(&ctx, digest, 32);
  return true;
}

static bool handle_blind_sign(const BenfenSignTx* msg, const HDNode* node,
                              BenfenSignedTx* resp) {
  char bfc_address[BFC_ADDR_SIZE] = {0};
  uint8_t digest[32] = {0};
  benfen_get_address_from_public_key(node->public_key + 1, bfc_address);
  if (!handle_hash(msg->raw_tx.bytes, msg->raw_tx.size, digest)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid raw tx");
    layoutHome();
    return false;
  }

  if (!layoutBlindSign("Benfen", false, NULL, bfc_address, msg->raw_tx.bytes,
                       msg->raw_tx.size, NULL, NULL, NULL, NULL, NULL, NULL)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    layoutHome();
    return false;
  }

  handle_signature(digest, node, resp);
  return true;
}

void benfen_sign_tx(const BenfenSignTx* msg, const HDNode* node,
                    BenfenSignedTx* resp) {
  if (!msg || !node || !resp) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid parameters");
    return;
  }
  if (handle_blind_sign(msg, node, resp)) {
    msg_write(MessageType_MessageType_BenfenSignedTx, resp);
  }
}

void benfen_message_sign(const BenfenSignMessage* msg, const HDNode* node,
                         BenfenMessageSignature* resp) {
  uint8_t digest[32] = {0};
  uint8_t num_bytes[32] = {0x3, 0x0, 0x0};
  int num_bytes_len = 3;
  uleb_encode(msg->message.size, num_bytes, &num_bytes_len);
  BLAKE2B_CTX ctx;
  blake2b_Init(&ctx, 32);
  blake2b_Update(&ctx, num_bytes, num_bytes_len);
  blake2b_Update(&ctx, msg->message.bytes, msg->message.size);
  blake2b_Final(&ctx, digest, 32);

#if EMULATOR
  ed25519_sign(digest, 32, node->private_key, resp->signature.bytes);
#else
  hdnode_sign(node, digest, 32, 0, resp->signature.bytes, NULL, NULL);
#endif
  resp->signature.size = 64;
  msg_write(MessageType_MessageType_BenfenMessageSignature, resp);
}

static inline void hash_data(const uint8_t* buf, size_t size) {
  blake2b_Update(&hash_ctx, buf, size);
}

static void send_signature(void) {
  uint8_t digest[32] = {0};
  BenfenSignedTx tx;
  char bfc_address[BFC_ADDR_SIZE] = {0};
  benfen_get_address_from_public_key(node_cache.public_key + 1, bfc_address);

  if (!layoutBlindSign("Benfen", false, NULL, bfc_address,
                       common_tx_data_buffer, global_data_chunk_size, NULL,
                       NULL, NULL, NULL, NULL, NULL)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled,
                    "Signing cancelled by user");
    benfen_signing_abort();
    return;
  }
  blake2b_Final(&hash_ctx, digest, 32);

#if EMULATOR
  ed25519_sign(digest, 32, node_cache.private_key, tx.signature.bytes);
#else
  hdnode_sign(&node_cache, digest, 32, 0, tx.signature.bytes, NULL, NULL);
#endif

  memcpy(tx.public_key.bytes, pubkey, 32);
  tx.signature.size = 64;
  tx.public_key.size = 32;
  msg_write(MessageType_MessageType_BenfenSignedTx, &tx);
  memzero(&node_cache, sizeof(node_cache));
  benfen_signing_abort();
}

static void send_request_chunk(void) {
  msg_tx_request.has_data_length = true;
  msg_tx_request.data_length = data_left <= 1024 ? data_left : 1024;
  msg_write(MessageType_MessageType_BenfenTxRequest, &msg_tx_request);
}

void benfen_signing_init(const BenfenSignTx* msg, const HDNode* node) {
  memzero(common_tx_data_buffer, MAX_COMMON_TX_DATA_SIZE);
  benfen_signing = true;
  blake2b_Init(&hash_ctx, 32);
  if ((msg->data_initial_chunk.bytes[0] != 0x00) &&
      ((msg->data_initial_chunk.bytes[1] != 0x00)) &&
      ((msg->data_initial_chunk.bytes[2] != 0x00))) {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid raw tx");
    benfen_signing_abort();
    return;
  }
  memcpy(common_tx_data_buffer, msg->data_initial_chunk.bytes,
         msg->data_initial_chunk.size);
  global_data_chunk_size = msg->data_initial_chunk.size;
  memcpy(&node_cache, node, sizeof(HDNode));
  memcpy(pubkey, node->public_key + 1, 32);
  hash_data(msg->data_initial_chunk.bytes, msg->data_initial_chunk.size);
  data_total = msg->data_length;
  data_left = data_total - msg->data_initial_chunk.size;
  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}

void benfen_signing_txack(BenfenTxAck* tx) {
  if (tx->data_chunk.size > data_left) {
    fsm_sendFailure(FailureType_Failure_DataError, "Too much data");
    benfen_signing_abort();
    return;
  }
  if (data_left > 0 && tx->data_chunk.size == 0) {
    fsm_sendFailure(FailureType_Failure_DataError, "Empty data chunk received");
    benfen_signing_abort();
    return;
  }

  if (global_data_chunk_size + tx->data_chunk.size >
      sizeof(common_tx_data_buffer)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Global buffer overflow");
    benfen_signing_abort();
    return;
  }

  memcpy(common_tx_data_buffer + global_data_chunk_size, tx->data_chunk.bytes,
         tx->data_chunk.size);
  global_data_chunk_size += tx->data_chunk.size;

  hash_data(tx->data_chunk.bytes, tx->data_chunk.size);
  data_left -= tx->data_chunk.size;

  if (data_left > 0) {
    send_request_chunk();
  } else {
    send_signature();
  }
}
void benfen_signing_abort(void) {
  if (benfen_signing) {
    memzero(&node_cache, sizeof(node_cache));
    memset(&node_cache, 0, sizeof(HDNode));
    data_left = 0;
    data_total = 0;
    layoutHome();
    benfen_signing = false;
  }
}