#!/usr/bin/env python3

# This file is part of the Trezor project.
#
# Copyright (C) 2012-2022 Onekey and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from typing import TYPE_CHECKING, Optional

import click

from .. import alephium, tools
from . import with_client

if TYPE_CHECKING:
    from ..client import TrezorClient

PATH_HELP = "BIP-32 path, e.g. m/44'/1234'/0'/0/0"


@click.group(name="alephium")
def cli():
    """alephium commands."""


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.option("-d", "--show-display", is_flag=True)
@click.option(
    "-p", "--include-public-key", is_flag=True, help="Include public key in the output"
)
@click.option(
    "-g", "--target-group", type=int, help="Target group for address derivation (0-3)"
)
@with_client
def get_address(
    client: "TrezorClient",
    address: str,
    show_display: bool,
    include_public_key: bool,
    target_group: int,
):
    """Get Alephium address and optionally public key for specified path."""
    address_n = tools.parse_path(address)
    result = alephium.get_address(
        client, address_n, show_display, include_public_key, target_group
    )
    click.echo(f"Address: {result.address}")
    if include_public_key and result.public_key:
        click.echo(f"Public Key: {result.public_key.hex()}")
    derived_path_str = "m/" + "/".join(str(i) for i in result.derived_path)
    click.echo(f"Derived Path: {derived_path_str}")

    return result


#
# Signing functions
#
@cli.command()
@click.option(
    "-n", "--address", required=True, help=PATH_HELP, default="m/44'/1234'/0'/0/0"
)
@click.argument("message")
@click.option("-d", "--data_length", help="data_length", type=int)
@with_client
def sign_tx(
    client: "TrezorClient", address: str, message: str, data_length: int
) -> Optional[str]:
    """Sign a hex-encoded raw message which is the data used to calculate the bip143-like sig-hash."""
    address_n = tools.parse_path(address)
    try:
        resp = alephium.sign_tx(client, address_n, message, data_length)
        if resp and hasattr(resp, "signature") and resp.signature:
            return resp.signature.hex()
        else:
            click.echo("Transaction signed, but no signature returned")
            return None
    except Exception as e:
        click.echo(f"Failed to sign transaction: {e}")
        return None


@cli.command()
@click.option("-n", "--address", required=True, help=PATH_HELP)
@click.argument("message")
@click.argument("message_type")
@with_client
def sign_message(
    client: "TrezorClient", address: str, message: str, message_type: str
) -> Optional[str]:
    """Sign message with Conflux address."""
    address_n = tools.parse_path(address)
    try:
        resp = alephium.sign_message(client, address_n, message, message_type)
        if resp and hasattr(resp, "signature") and resp.signature:
            return resp.signature.hex()
        else:
            click.echo("Message signed, but no signature returned")
            return None
    except Exception as e:
        click.echo(f"Failed to sign message: {e}")
        return None
