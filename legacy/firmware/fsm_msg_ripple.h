/*
 * This file is part of the OneKey project, https://onekey.so/
 *
 * Copyright (C) 2022 OneKey Team <core@onekey.so>
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
#undef COIN_TYPE
#define COIN_TYPE 144
void fsm_msgRippleGetAddress(RippleGetAddress *msg) {
  RESP_INIT(RippleAddress);

  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;
  if (hdnode_fill_public_key(node) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive public key");
    layoutHome();
    return;
  }

  if (!get_ripple_address(node->public_key, resp->address)) {
    fsm_sendFailure(FailureType_Failure_DataError, "Get address failed");
    return;
  }
  if (msg->has_show_display && msg->show_display) {
    char desc[64] = {0};
    strlcpy(desc, _(T__CHAIN_STR_ADDRESS), sizeof(desc));
    bracket_replace(desc, "Ripple");
    if (!fsm_layoutAddress(resp->address, NULL, desc, false, 0, msg->address_n,
                           msg->address_n_count, false, NULL, 0, 0, NULL)) {
      return;
    }
  }

  msg_write(MessageType_MessageType_RippleAddress, resp);
  layoutHome();
}

void fsm_msgRippleSignTx(RippleSignTx *msg) {
  RESP_INIT(RippleSignedTx);

  CHECK_INITIALIZED
  CHECK_PARAM(fsm_common_path_check(msg->address_n, msg->address_n_count,
                                    COIN_TYPE, SECP256K1_NAME, true),
              "Invalid path");
  CHECK_PIN

  HDNode *node = fsm_getDerivedNode(SECP256K1_NAME, msg->address_n,
                                    msg->address_n_count, NULL);
  if (!node) return;

  if (hdnode_fill_public_key(node) != 0) {
    fsm_sendFailure(FailureType_Failure_ProcessError,
                    "Failed to derive public key");
    layoutHome();
    return;
  }

  if (ripple_sign_tx(msg, node, resp)) {
    msg_write(MessageType_MessageType_RippleSignedTx, resp);
  } else {
    fsm_sendFailure(FailureType_Failure_DataError, "Signing failed");
  }

  layoutHome();
}
