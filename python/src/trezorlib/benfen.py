# This file is part of the OneKey project, https://onekey.so/
#
# Copyright (C) 2021 OneKey Team <core@onekey.so>
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.


from typing import TYPE_CHECKING, AnyStr

from . import messages
from .tools import expect, prepare_message_bytes

if TYPE_CHECKING:
    from .client import TrezorClient
    from .tools import Address
    from .protobuf import MessageType


@expect(messages.BenfenAddress, field="address", ret_type=str)
def get_address(
    client: "TrezorClient", address_n: "Address", show_display: bool = False
) -> "MessageType":
    return client.call(
        messages.BenfenGetAddress(address_n=address_n, show_display=show_display)
    )


# @expect(messages.BenfenSignedTx)
# def sign_tx(client: "TrezorClient", address_n: "Address", raw_tx: bytes,coin_type: bytes ):
#     return client.call(messages.BenfenSignTx(address_n=address_n, raw_tx=raw_tx,coin_type=coin_type))


# @expect(messages.BenfenSignedTx)
# def sign_tx(
#     client: "TrezorClient",
#     address_n: "Address",
#     data_initial_chunk: bytes,
#     coin_type: bytes,
#     data_length: int,
# ):

#     length = len(data_initial_chunk)
#     print(f"Data length: {length} bytes")
#     resp = client.call(
#         messages.BenfenSignTx(
#             address_n=address_n,
#             raw_tx=b"",
#             data_initial_chunk=data_initial_chunk,
#             coin_type=coin_type,
#             data_length=data_length,
#         )
#     )
#     while isinstance(resp, messages.BenfenTxRequest):
#         print("ack request")
#         data_chunk = bytes.fromhex("000000000000")
#         resp = client.call(messages.BenfenTxAck(data_chunk=data_chunk))
#     return resp


@expect(messages.BenfenSignedTx)
def sign_tx(
    client: "TrezorClient",
    address_n: "Address",
    data_initial_chunk: bytes,
    coin_type: bytes,
    data_length: int,
):

    length = len(data_initial_chunk)
    print(f"Data length: {length} bytes")
    resp = client.call(
        messages.BenfenSignTx(
            address_n=address_n,
            raw_tx=data_initial_chunk,
            coin_type=coin_type,
        )
    )
    return resp


@expect(messages.BenfenMessageSignature)
def sign_message(
    client: "TrezorClient",
    n: "Address",
    message: AnyStr,
) -> "MessageType":
    return client.call(
        messages.BenfenSignMessage(
            address_n=n,
            message=prepare_message_bytes(message),
        )
    )


# @expect(messages.AlephiumMessageSignature)
# def sign_message(
#     client: "TrezorClient", address_n: "Address", message: str, message_type: str
# ):
#     message_bytes = message.encode("utf-8")
#     message_type_bytes = message_type.encode("utf-8")
#     resp = client.call(
#         messages.AlephiumSignMessage(
#             address_n=address_n, message=message_bytes, message_type=message_type_bytes
#         )
#     )
#     return resp
