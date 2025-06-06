/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#include "address.h"
#include "base58.h"
#include "buttons.h"
#include "crypto.h"
#include "ecdsa.h"
#include "fsm.h"
#include "gettext.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "protect.h"
#include "se_chip.h"
#include "secp256k1.h"
#include "sha2.h"
#include "transaction.h"
#include "tron.h"
#include "util.h"

#include <pb_decode.h>

// PROTOBUF3 types
#define PROTO_TYPE_VARINT 0
#define PROTO_TYPE_STRING 2

extern int ethereum_is_canonic(uint8_t v, uint8_t signature[64]);

void tron_message_hash(const uint8_t *message, size_t message_len,
                       uint8_t hash[32]) {
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, (const uint8_t *)"\x19" "TRON Signed Message:\n32", 24);
  sha3_Update(&ctx, message, message_len);
  keccak_Final(&ctx, hash);
}

void tron_message_sign(TronSignMessage *msg, const HDNode *node,
                       TronMessageSignature *resp) {
  uint8_t hash[32];
  uint8_t msg_hash[32];

  // hash the message
  struct SHA3_CTX ctx = {0};
  sha3_256_Init(&ctx);
  sha3_Update(&ctx, msg->message.bytes, msg->message.size);
  keccak_Final(&ctx, msg_hash);

  tron_message_hash(msg_hash, 32, hash);

  uint8_t v;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return;
  }

  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  msg_write(MessageType_MessageType_TronMessageSignature, resp);
}

int tron_eth_2_trx_address(const uint8_t eth_address[20], char *str,
                           int strsize) {
  uint8_t address_bytes[21];
  address_bytes[0] = 0x41;  // Tron address prefix
  memcpy(&address_bytes[1], eth_address, 20);

  int r = base58_encode_check(address_bytes, sizeof(address_bytes),
                              HASHER_SHA2D, str, strsize);
  return r;
}

int add_field(uint8_t *buf, int *index, uint8_t fnumber, uint8_t ftype) {
  int ret = *index;

  if (fnumber > 15) {
    buf[*index] = fnumber << 3 | ftype;
    *index += 1;
    buf[*index] = 0x1;
    *index += 1;
  } else {
    buf[*index] = fnumber << 3 | ftype;
    *index += 1;
  }

  return *index - ret;
}

int write_varint(uint8_t *buf, int *index, uint64_t value) {
  int ret = *index;
  uint8_t byte = 0;
  uint64_t v = value;

  while (1) {
    byte = v & 0x7F;
    v = v >> 7;
    if (v == 0) {
      buf[*index] = byte;
      *index += 1;
      break;
    }
    buf[*index] = byte | 0x80;
    *index += 1;
  }

  return *index - ret;
}

int write_bytes_with_length(uint8_t *buf, int *index, uint8_t *bytes, int len) {
  int ret = *index;

  write_varint(buf, index, len);
  for (int i = 0; i < len; i++) {
    buf[*index] = bytes[i];
    *index += 1;
  }

  return *index - ret;
}

int write_bytes_without_length(uint8_t *buf, int *index, uint8_t *bytes,
                               int len) {
  int ret = *index;

  for (int i = 0; i < len; i++) {
    buf[*index] = bytes[i];
    *index += 1;
  }

  return *index - ret;
}

int pack_contract(TronSignTx *msg, uint8_t *buf, int *index,
                  const char *owner_address) {
  // Pack Tron Proto3 Contract
  // See: https://github.com/tronprotocol/protocol/blob/master/core/Tron.proto
  // and
  // https://github.com/tronprotocol/protocol/blob/master/core/contract/smart_contract.proto

  int ret = *index, len = 0, cmessage_len = 0, cmessage_index = 0, capi_len = 0,
      capi_index = 0;
  uint8_t cmessage[1024] = {0};
  uint8_t capi[64] = {0};
  uint8_t addr_raw[MAX_ADDR_RAW_SIZE] = {0};

  add_field(buf, index, 1, PROTO_TYPE_VARINT);
  if (msg->contract.has_transfer_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.TransferContract", 45);

    write_varint(buf, index, 1);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_STRING);
    len = base58_decode_check(msg->contract.transfer_contract.to_address,
                              HASHER_SHA2D, addr_raw, MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);
    cmessage_len += add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
    cmessage_len += write_varint(cmessage, &cmessage_index,
                                 msg->contract.transfer_contract.amount);
  } else if (msg->contract.has_vote_witness_contract) {
    write_varint(buf, index, 4);
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.VoteWitnessContract", 48);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);
    int votes_count = msg->contract.vote_witness_contract.votes_count;
    for (int i = 0; i < votes_count; i++) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_STRING);
      uint8_t v_message[64] = {0};
      int v_message_index = 0, v_message_len = 0;
      Vote vote = msg->contract.vote_witness_contract.votes[i];
      v_message_len +=
          add_field(v_message, &v_message_index, 1, PROTO_TYPE_STRING);
      len = base58_decode_check(vote.vote_address, HASHER_SHA2D, addr_raw,
                                MAX_ADDR_RAW_SIZE);
      v_message_len +=
          write_bytes_with_length(v_message, &v_message_index, addr_raw, len);
      v_message_len +=
          add_field(v_message, &v_message_index, 2, PROTO_TYPE_VARINT);
      v_message_len +=
          write_varint(v_message, &v_message_index, vote.vote_count);
      cmessage_len += write_bytes_with_length(cmessage, &cmessage_index,
                                              v_message, v_message_len);
    }
    if (msg->contract.vote_witness_contract.has_support) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       (uint8_t)msg->contract.vote_witness_contract.support);
    }
  } else if (msg->contract.has_trigger_smart_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.TriggerSmartContract", 49);

    write_varint(buf, index, 31);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_STRING);
    len = base58_decode_check(
        msg->contract.trigger_smart_contract.contract_address, HASHER_SHA2D,
        addr_raw, MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    if (msg->contract.trigger_smart_contract.call_value) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.trigger_smart_contract.call_value);
    }

    // Contract data
    cmessage_len += add_field(cmessage, &cmessage_index, 4, PROTO_TYPE_STRING);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index,
                                msg->contract.trigger_smart_contract.data.bytes,
                                msg->contract.trigger_smart_contract.data.size);
    if (msg->contract.trigger_smart_contract.call_token_value) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 5, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.trigger_smart_contract.call_token_value);
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 6, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.trigger_smart_contract.asset_id);
    }
  } else if (msg->contract.has_freeze_balance_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.FreezeBalanceContract", 50);

    write_varint(buf, index, 11);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.freeze_balance_contract.frozen_balance);
    cmessage_len += add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.freeze_balance_contract.frozen_duration);
    if (msg->contract.freeze_balance_contract.has_resource) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 10, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.freeze_balance_contract.resource);
    }
    if (msg->contract.freeze_balance_contract.has_receiver_address) {
      uint8_t receiver_raw[MAX_ADDR_RAW_SIZE] = {0};
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 15, PROTO_TYPE_STRING);
      len = base58_decode_check(
          msg->contract.freeze_balance_contract.receiver_address, HASHER_SHA2D,
          receiver_raw, MAX_ADDR_RAW_SIZE);
      cmessage_len +=
          write_bytes_with_length(cmessage, &cmessage_index, receiver_raw, len);
    }
  } else if (msg->contract.has_unfreeze_balance_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.UnfreezeBalanceContract", 52);

    write_varint(buf, index, 12);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    if (msg->contract.unfreeze_balance_contract.has_resource) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 10, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.unfreeze_balance_contract.resource);
    }
    if (msg->contract.unfreeze_balance_contract.has_receiver_address) {
      uint8_t receiver_raw[MAX_ADDR_RAW_SIZE] = {0};
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 15, PROTO_TYPE_STRING);
      len = base58_decode_check(
          msg->contract.unfreeze_balance_contract.receiver_address,
          HASHER_SHA2D, receiver_raw, MAX_ADDR_RAW_SIZE);
      cmessage_len +=
          write_bytes_with_length(cmessage, &cmessage_index, receiver_raw, len);
    }
  } else if (msg->contract.has_withdraw_balance_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.WithdrawBalanceContract", 52);
    write_varint(buf, index, 13);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);
  } else if (msg->contract.has_freeze_balance_v2_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.FreezeBalanceV2Contract", 52);

    write_varint(buf, index, 54);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.freeze_balance_v2_contract.frozen_balance);

    if (msg->contract.freeze_balance_v2_contract.has_resource) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.freeze_balance_v2_contract.resource);
    }
  } else if (msg->contract.has_unfreeze_balance_v2_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.UnfreezeBalanceV2Contract",
        54);
    write_varint(buf, index, 55);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_VARINT);
    cmessage_len += write_varint(
        cmessage, &cmessage_index,
        msg->contract.unfreeze_balance_v2_contract.unfreeze_balance);

    if (msg->contract.unfreeze_balance_v2_contract.has_resource) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.unfreeze_balance_v2_contract.resource);
    }
  } else if (msg->contract.has_withdraw_expire_unfreeze_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t
             *)"type.googleapis.com/protocol.WithdrawExpireUnfreezeContract",
        59);
    write_varint(buf, index, 56);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);
  } else if (msg->contract.has_delegate_resource_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.DelegateResourceContract", 53);
    write_varint(buf, index, 57);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.delegate_resource_contract.resource);
    cmessage_len += add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.delegate_resource_contract.balance);
    if (msg->contract.delegate_resource_contract.has_receiver_address) {
      uint8_t receiver_raw[MAX_ADDR_RAW_SIZE] = {0};
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 4, PROTO_TYPE_STRING);
      len = base58_decode_check(
          msg->contract.delegate_resource_contract.receiver_address,
          HASHER_SHA2D, receiver_raw, MAX_ADDR_RAW_SIZE);
      cmessage_len +=
          write_bytes_with_length(cmessage, &cmessage_index, receiver_raw, len);
    }
    if (msg->contract.delegate_resource_contract.has_lock) {
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 5, PROTO_TYPE_VARINT);
      cmessage_len +=
          write_varint(cmessage, &cmessage_index,
                       msg->contract.delegate_resource_contract.lock);
    }
  } else if (msg->contract.has_undelegate_resource_contract) {
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.UnDelegateResourceContract",
        55);
    write_varint(buf, index, 58);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);

    cmessage_len += add_field(cmessage, &cmessage_index, 2, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.undelegate_resource_contract.resource);
    cmessage_len += add_field(cmessage, &cmessage_index, 3, PROTO_TYPE_VARINT);
    cmessage_len +=
        write_varint(cmessage, &cmessage_index,
                     msg->contract.undelegate_resource_contract.balance);
    if (msg->contract.undelegate_resource_contract.has_receiver_address) {
      uint8_t receiver_raw[MAX_ADDR_RAW_SIZE] = {0};
      cmessage_len +=
          add_field(cmessage, &cmessage_index, 4, PROTO_TYPE_STRING);
      len = base58_decode_check(
          msg->contract.undelegate_resource_contract.receiver_address,
          HASHER_SHA2D, receiver_raw, MAX_ADDR_RAW_SIZE);
      cmessage_len +=
          write_bytes_with_length(cmessage, &cmessage_index, receiver_raw, len);
    }
  } else if (msg->contract.has_cancel_all_unfreeze_v2_contract) {
    write_varint(buf, index, 59);
    capi_len += add_field(capi, &capi_index, 1, PROTO_TYPE_STRING);
    capi_len += write_bytes_with_length(
        capi, &capi_index,
        (uint8_t *)"type.googleapis.com/protocol.CancelAllUnfreezeV2Contract",
        56);

    cmessage_len += add_field(cmessage, &cmessage_index, 1, PROTO_TYPE_STRING);
    len = base58_decode_check(owner_address, HASHER_SHA2D, addr_raw,
                              MAX_ADDR_RAW_SIZE);
    cmessage_len +=
        write_bytes_with_length(cmessage, &cmessage_index, addr_raw, len);
  }

  uint8_t tmp[8] = {0};
  int cmessage_varint_len = 0;
  write_varint(tmp, &cmessage_varint_len, cmessage_len);

  add_field(buf, index, 2, PROTO_TYPE_STRING);
  write_varint(buf, index, capi_len + cmessage_len + 1 + cmessage_varint_len);
  write_bytes_without_length(buf, index, capi, capi_len);
  add_field(buf, index, 2, PROTO_TYPE_STRING);
  write_varint(buf, index, cmessage_len);
  write_bytes_without_length(buf, index, cmessage, cmessage_len);

  if (msg->contract.has_provider) {
    add_field(buf, index, 3, PROTO_TYPE_STRING);
    write_bytes_with_length(buf, index, msg->contract.provider.bytes,
                            msg->contract.provider.size);
  }
  if (msg->contract.has_contract_name) {
    add_field(buf, index, 4, PROTO_TYPE_STRING);
    write_bytes_with_length(buf, index, msg->contract.contract_name.bytes,
                            msg->contract.contract_name.size);
  }
  if (msg->contract.has_permission_id) {
    add_field(buf, index, 5, PROTO_TYPE_VARINT);
    write_varint(buf, index, msg->contract.permission_id);
  }
  return *index - ret;
}

void serialize(TronSignTx *msg, uint8_t *buf, int *index,
               const char *owner_address) {
  // transaction parameters
  add_field(buf, index, 1, PROTO_TYPE_STRING);
  write_bytes_with_length(buf, index, msg->ref_block_bytes.bytes,
                          msg->ref_block_bytes.size);
  add_field(buf, index, 4, PROTO_TYPE_STRING);
  write_bytes_with_length(buf, index, msg->ref_block_hash.bytes,
                          msg->ref_block_hash.size);
  add_field(buf, index, 8, PROTO_TYPE_VARINT);
  write_varint(buf, index, msg->expiration);
  if (msg->has_data) {
    add_field(buf, index, 10, PROTO_TYPE_STRING);
    write_bytes_with_length(buf, index, msg->data.bytes, msg->data.size);
  }

  // add Contract
  add_field(buf, index, 11, PROTO_TYPE_STRING);
  int current_index = *index, contract_len = 0;
  contract_len = pack_contract(msg, buf, index, owner_address);
  *index = current_index;
  write_varint(buf, index, contract_len);
  pack_contract(msg, buf, index, owner_address);

  // add timestamp
  add_field(buf, index, 14, PROTO_TYPE_VARINT);
  write_varint(buf, index, msg->timestamp);
  // add fee_limit if any
  if (msg->has_fee_limit) {
    add_field(buf, index, 18, PROTO_TYPE_VARINT);
    write_varint(buf, index, msg->fee_limit);
  }
}

bool layoutFreezeSign(TronSignTx *msg) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t key = KEY_NULL;
  uint8_t max_index = 0;
  char amount_str[60];
  char duration_str[32];
  const char **tx_msg = format_tx_message("TRON");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  if (msg->contract.has_freeze_balance_contract) {
    max_index = 5;
    tron_format_amount(msg->contract.freeze_balance_contract.frozen_balance,
                       amount_str, sizeof(amount_str));
    uint2str(msg->contract.freeze_balance_contract.frozen_duration,
             duration_str);
  } else if (msg->contract.has_unfreeze_balance_contract) {
    max_index = 3;
  } else {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;

  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__TYPE_COLON), FONT_STANDARD);
    if (msg->contract.has_freeze_balance_contract) {
      oledDrawStringAdapter(0, y + 10, "Freeze", FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, "UnFreeze", FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    if (msg->contract.has_freeze_balance_contract) {
      oledDrawStringAdapter(0, y, _(I__BALANCE_COLON), FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, amount_str, FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y, _(I__RESOURCE_COLON), FONT_STANDARD);
      if (msg->contract.unfreeze_balance_contract.resource ==
          TronResourceCode_BANDWIDTH) {
        oledDrawStringAdapter(0, y + 10, __("BANDWIDTH"), FONT_STANDARD);
      } else {
        oledDrawStringAdapter(0, y + 10, __("ENERGY"), FONT_STANDARD);
      }
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    layoutTxConfirmPage(tx_msg[1]);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    if (msg->contract.has_freeze_balance_contract) {
      oledDrawStringAdapter(0, y, "Frozen duration:", FONT_STANDARD);
      oledDrawStringAdapter(0, y + 10, duration_str, FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y, _(I__RECEIVER_COLON), FONT_STANDARD);
      oledDrawStringAdapter(
          0, y + 10, msg->contract.unfreeze_balance_contract.receiver_address,
          FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 3) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__RESOURCE_COLON), FONT_STANDARD);
    if (msg->contract.freeze_balance_contract.resource ==
        TronResourceCode_BANDWIDTH) {
      oledDrawStringAdapter(0, y + 10, __("BANDWIDTH"), FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, __("ENERGY"), FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 4) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__RECEIVER_COLON), FONT_STANDARD);
    oledDrawStringAdapter(
        0, y + 10, msg->contract.freeze_balance_contract.receiver_address,
        FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      goto refresh_menu;
    case KEY_DOWN:
      goto refresh_menu;
    case KEY_CONFIRM:
      if (max_index == index) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_menu;
    case KEY_CANCEL:
      if (0 == index || max_index == index) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    default:
      break;
  }

  return result;
}

bool layoutFreezeV2Sign(TronSignTx *msg) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t key = KEY_NULL;
  uint8_t max_index = 3;
  TronResourceCode resource;
  char amount_str[60];
  const char **tx_msg = format_tx_message("TRON");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  if (msg->contract.has_freeze_balance_v2_contract) {
    tron_format_amount(msg->contract.freeze_balance_v2_contract.frozen_balance,
                       amount_str, sizeof(amount_str));
    resource = msg->contract.freeze_balance_v2_contract.resource;
  } else if (msg->contract.has_unfreeze_balance_v2_contract) {
    tron_format_amount(
        msg->contract.unfreeze_balance_v2_contract.unfreeze_balance, amount_str,
        sizeof(amount_str));
    resource = msg->contract.unfreeze_balance_v2_contract.resource;
  } else {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;

  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__TYPE_COLON), FONT_STANDARD);
    if (msg->contract.has_freeze_balance_v2_contract) {
      oledDrawStringAdapter(0, y + 10, "Freeze Balance V2 Contract",
                            FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, "UnFreeze Balance V2 Contract",
                            FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__BALANCE_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__RESOURCE_COLON), FONT_STANDARD);
    if (resource == TronResourceCode_BANDWIDTH) {
      oledDrawStringAdapter(0, y + 10, __("BANDWIDTH"), FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, __("ENERGY"), FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      goto refresh_menu;
    case KEY_DOWN:
      goto refresh_menu;
    case KEY_CONFIRM:
      if (max_index == index) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_menu;
    case KEY_CANCEL:
      if (0 == index || max_index == index) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    default:
      break;
  }

  return result;
}

bool layoutDelegateResourceSign(TronSignTx *msg) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t key = KEY_NULL;
  uint8_t max_index = 0;
  char amount_str[60];
  const char **tx_msg = format_tx_message("TRON");

  TronResourceCode resource;
  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

  if (msg->contract.has_delegate_resource_contract) {
    max_index = 5;
    tron_format_amount(msg->contract.delegate_resource_contract.balance,
                       amount_str, sizeof(amount_str));
    resource = msg->contract.delegate_resource_contract.resource;
  } else if (msg->contract.has_undelegate_resource_contract) {
    max_index = 4;
    tron_format_amount(msg->contract.undelegate_resource_contract.balance,
                       amount_str, sizeof(amount_str));
    resource = msg->contract.undelegate_resource_contract.resource;
  } else {
    return false;
  }

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;

  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__TYPE_COLON), FONT_STANDARD);
    if (msg->contract.has_delegate_resource_contract) {
      oledDrawStringAdapter(0, y + 10, "Delegate Resource Contract",
                            FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, "UnDelegate Resource Contract",
                            FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__RESOURCE_COLON), FONT_STANDARD);
    if (resource == TronResourceCode_BANDWIDTH) {
      oledDrawStringAdapter(0, y + 10, __("BANDWIDTH"), FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, __("ENERGY"), FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 2) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__BALANCE_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, amount_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 3) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__RECEIVER_COLON), FONT_STANDARD);
    if (msg->contract.has_delegate_resource_contract) {
      oledDrawStringAdapter(
          0, y + 10, msg->contract.delegate_resource_contract.receiver_address,
          FONT_STANDARD);
    } else {
      oledDrawStringAdapter(
          0, y + 10,
          msg->contract.undelegate_resource_contract.receiver_address,
          FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (max_index == index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index == 4) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, __("Lock:"), FONT_STANDARD);
    if (msg->contract.delegate_resource_contract.lock) {
      oledDrawStringAdapter(0, y + 10, "True", FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, "False", FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  key = protectWaitKey(0, 0);
  switch (key) {
    case KEY_UP:
      goto refresh_menu;
    case KEY_DOWN:
      goto refresh_menu;
    case KEY_CONFIRM:
      if (max_index == index) {
        result = true;
        break;
      }
      if (index < max_index) {
        index++;
      }
      goto refresh_menu;
    case KEY_CANCEL:
      if (0 == index || max_index == index) {
        result = false;
        break;
      }
      if (index > 0) {
        index--;
      }
      goto refresh_menu;
    default:
      break;
  }

  return result;
}

bool layoutVoteWitnessSign(const TronVoteWitnessContract *contract,
                           const char *signer_str) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t vote_count = contract->votes_count;
  uint8_t max_index = vote_count * 2 + 2;
  uint8_t bubble_key;
  const char **tx_msg = format_tx_message("TRON");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  bubble_key = KEY_NULL;

  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__TYPE_COLON), FONT_STANDARD);
    if (contract->has_support && !contract->support) {
      oledDrawStringAdapter(0, y + 10, "Remove Vote Witness", FONT_STANDARD);
    } else {
      oledDrawStringAdapter(0, y + 10, "Vote Witness", FONT_STANDARD);
    }
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__VOTER_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == max_index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  } else if (index % 2 == 0) {
    layoutHeader(tx_msg[0]);
    char candidate_item_name[64];
    if (vote_count > 1) {
      uint8_t candidate_item_index = (index - 2) / 2 + 1;
      snprintf(candidate_item_name, sizeof(candidate_item_name), "%s #%d",
               _(GLOBAL_CANDIDATE), candidate_item_index);
    } else {
      strlcpy(candidate_item_name, _(GLOBAL_CANDIDATE),
              sizeof(candidate_item_name));
    }
    oledDrawStringAdapter(0, y, candidate_item_name, FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10,
                          contract->votes[(index - 2) / 2].vote_address,
                          FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);

  } else {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(GLOBAL__VOTE_COUNT), FONT_STANDARD);
    char vote_count_str[64] = {0};
    snprintf(vote_count_str, sizeof(vote_count_str), "%ld",
             (contract->votes[(index - 3) / 2].vote_count));
    oledDrawStringAdapter(0, y + 10, vote_count_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  }
  oledRefresh();

  HANDLE_KEY(bubble_key)
}

bool layoutCancelAllUnfreezeV2Sign(const char *signer_str) {
  bool result = false;
  int index = 0;
  int y = 0;
  uint8_t max_index = 2;
  uint8_t bubble_key;
  const char **tx_msg = format_tx_message("TRON");

  ButtonRequest resp = {0};
  memzero(&resp, sizeof(ButtonRequest));
  resp.has_code = true;
  resp.code = ButtonRequestType_ButtonRequest_SignTx;
  msg_write(MessageType_MessageType_ButtonRequest, &resp);

refresh_menu:
  layoutSwipe();
  oledClear();
  y = 13;
  bubble_key = KEY_NULL;

  if (index == 0) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__TYPE_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, "Cancel All UnStaking", FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == 1) {
    layoutHeader(tx_msg[0]);
    oledDrawStringAdapter(0, y, _(I__SIGNER_COLON), FONT_STANDARD);
    oledDrawStringAdapter(0, y + 10, signer_str, FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_arrow);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_arrow);
  } else if (index == max_index) {
    layoutHeader(_(T__SIGN_TRANSACTION));
    oledDrawStringAdapter(0, 13, tx_msg[1], FONT_STANDARD);
    layoutButtonNoAdapter(NULL, &bmp_bottom_left_close);
    layoutButtonYesAdapter(NULL, &bmp_bottom_right_confirm);
  }
  oledRefresh();

  HANDLE_KEY(bubble_key)
}

bool tron_sign_tx(TronSignTx *msg, const char *owner_address,
                  const HDNode *node, TronSignedTx *resp) {
  ConstTronTokenPtr token = NULL;
  uint64_t amount = 0;
  uint8_t value_bytes[32];
  char to_str[36];
  char signer_str[36];
  uint8_t eth_address[20];
  const char **tx_msg = format_tx_message("TRON");
  if (!hdnode_get_ethereum_pubkeyhash(node, eth_address)) return false;
  tron_eth_2_trx_address(eth_address, signer_str, sizeof(signer_str));

  int index = 0;
  uint8_t *raw = resp->serialized_tx.bytes;

  if (msg->contract.has_transfer_contract) {
    if (msg->contract.transfer_contract.has_amount) {
      amount = msg->contract.transfer_contract.amount;
    }
    if (msg->contract.transfer_contract.has_to_address) {
      strlcpy(to_str, msg->contract.transfer_contract.to_address,
              sizeof(to_str));
    }
  } else if (msg->contract.has_trigger_smart_contract) {
    if (!msg->contract.trigger_smart_contract.has_data) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid TRON contract call data");
      return false;
    }
    if (msg->contract.trigger_smart_contract.data.size < 4) {
      fsm_sendFailure(FailureType_Failure_DataError,
                      "Invalid TRON contract call data");
      return false;
    }

    // detect TRC-20 like token
    if (msg->contract.trigger_smart_contract.data.size == 68 &&
        memcmp(
            msg->contract.trigger_smart_contract.data.bytes,
            "\xa9\x05\x9c\xbb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            16) == 0) {
      token = get_tron_token_by_address(
          msg->contract.trigger_smart_contract.contract_address);
      if (tron_eth_2_trx_address(
              &msg->contract.trigger_smart_contract.data.bytes[4 + 12], to_str,
              sizeof(to_str)) < 34) {
        fsm_sendFailure(FailureType_Failure_DataError,
                        "Failed to encode to TRON address");
        return false;
      }
      memcpy(value_bytes,
             &msg->contract.trigger_smart_contract.data.bytes[4 + 32], 32);
    } else {
      memcpy(to_str, msg->contract.trigger_smart_contract.contract_address, 36);
    }
  } else if (msg->contract.has_freeze_balance_contract) {
    if (!layoutFreezeSign(msg)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      layoutHome();
      return false;
    }
  } else if (msg->contract.has_unfreeze_balance_contract) {
    if (!layoutFreezeSign(msg)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      return false;
    }
  } else if (msg->contract.has_withdraw_balance_contract) {
    layoutDialogAdapterEx(tx_msg[0], &bmp_bottom_left_close, NULL,
                          &bmp_bottom_right_arrow, NULL, NULL, _(I__TYPE_COLON),
                          "Withdraw Balance Contract", NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
    layoutDialogAdapterEx(_(T__SIGN_TRANSACTION), &bmp_bottom_left_close, NULL,
                          &bmp_bottom_right_confirm, NULL, NULL, tx_msg[1],
                          NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
  } else if (msg->contract.has_freeze_balance_v2_contract ||
             msg->contract.has_unfreeze_balance_v2_contract) {
    if (!layoutFreezeV2Sign(msg)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      return false;
    }
  } else if (msg->contract.has_withdraw_expire_unfreeze_contract) {
    layoutDialogAdapterEx(tx_msg[0], &bmp_bottom_left_close, NULL,
                          &bmp_bottom_right_arrow, NULL, NULL, _(I__TYPE_COLON),
                          "Withdraw Expire Unfreeze Contract", NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
    layoutDialogAdapterEx(_(T__SIGN_TRANSACTION), &bmp_bottom_left_close, NULL,
                          &bmp_bottom_right_confirm, NULL, NULL, tx_msg[1],
                          NULL, NULL, NULL);
    if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
      return false;
    }
  } else if (msg->contract.has_delegate_resource_contract ||
             msg->contract.has_undelegate_resource_contract) {
    if (!layoutDelegateResourceSign(msg)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      return false;
    }
  } else if (msg->contract.has_vote_witness_contract) {
    if (!layoutVoteWitnessSign(&msg->contract.vote_witness_contract,
                               signer_str)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      return false;
    }
  } else if (msg->contract.has_cancel_all_unfreeze_v2_contract) {
    if (!layoutCancelAllUnfreezeV2Sign(signer_str)) {
      fsm_sendFailure(FailureType_Failure_ActionCancelled, "Signing cancelled");
      return false;
    }
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Invalid parameters");
    return false;
  }

  if (msg->contract.has_transfer_contract ||
      msg->contract.has_trigger_smart_contract) {
    char amount_str[60];
    int to_len = strlen(to_str);
    if (0 == to_len) strlcpy(to_str, "to new contract?", sizeof(to_str));
    if (token == NULL) {
      if (amount == 0 && msg->contract.has_trigger_smart_contract) {
        strcpy(amount_str, "message");
      } else {
        tron_format_amount(amount, amount_str, sizeof(amount_str));
        if (!layoutTransactionSign("TRON", 0, false, amount_str, to_str,
                                   signer_str, NULL, NULL, NULL, 0, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL, NULL)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          return false;
        }
      }
    } else {
      bignum256 val;
      bn_read_be(value_bytes, &val);
      tron_format_token_amount(&val, token, amount_str, sizeof(amount_str));

      if (msg->has_fee_limit) {
        char gas_value[32];
        tron_format_amount(msg->fee_limit, gas_value, sizeof(gas_value));
        if (!layoutTransactionSign("TRON", 0, true, amount_str, to_str,
                                   signer_str, NULL, NULL, NULL, 0,
                                   _(I__ETH_MAXIMUM_FEE_COLON), gas_value, NULL,
                                   NULL, NULL, NULL, NULL, NULL)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          return false;
        }
      } else {
        if (!layoutTransactionSign("TRON", 0, true, amount_str, to_str,
                                   signer_str, NULL, NULL, NULL, 0, NULL, NULL,
                                   NULL, NULL, NULL, NULL, NULL, NULL)) {
          fsm_sendFailure(FailureType_Failure_ActionCancelled,
                          "Signing cancelled");
          return false;
        }
      }
    }
    if ((token == NULL) && (msg->contract.has_trigger_smart_contract)) {
      if (!layoutBlindSign("TRON", true, to_str, signer_str,
                           msg->contract.trigger_smart_contract.data.bytes,
                           msg->contract.trigger_smart_contract.data.size, NULL,
                           NULL, NULL, NULL, NULL, NULL)) {
        fsm_sendFailure(FailureType_Failure_ActionCancelled,
                        "Signing cancelled");
        return false;
      }
    }
  }

  serialize(msg, raw, &index, owner_address);

  // hash the tx
  uint8_t hash[32];
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, raw, index);
  sha256_Final(&ctx, hash);

  // sign tx hash
  uint8_t v;
#if EMULATOR
  if (ecdsa_sign_digest(&secp256k1, node->private_key, hash,
                        resp->signature.bytes, &v, ethereum_is_canonic) != 0) {
#else
  if (hdnode_sign_digest(node, hash, resp->signature.bytes, &v,
                         ethereum_is_canonic) != 0) {
#endif
    fsm_sendFailure(FailureType_Failure_ProcessError, "Signing failed");
    return false;
  }

  // fill response
  resp->signature.bytes[64] = 27 + v;
  resp->signature.size = 65;
  resp->has_serialized_tx = 1;
  resp->serialized_tx.size = index;

  return true;
}

void tron_format_amount(const uint64_t amount, char *buf, int buflen) {
  char str_amount[12] = {0};
  bn_format_uint64(amount, NULL, NULL, 6, 0, false, 0, str_amount,
                   sizeof(str_amount));
  snprintf(buf, buflen, "%s TRX", str_amount);
}

void tron_format_token_amount(const bignum256 *amnt, ConstTronTokenPtr token,
                              char *buf, int buflen) {
  if (token == NULL) {
    strlcpy(buf, "Unknown token value", buflen);
    return;
  }
  bn_format(amnt, NULL, token->ticker, token->decimals, 0, false, 0, buf,
            buflen);
}
