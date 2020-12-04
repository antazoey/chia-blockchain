from typing import List
import click

from blspy import AugSchemeMPL, G1Element, G2Element

from src.cmds.init import check_keys
from src.options import default_options
from src.util.chech32 import encode_puzzle_hash
from src.util.keychain import (
    generate_mnemonic,
    bytes_to_mnemonic,
    Keychain,
)
from src.wallet.derive_keys import (
    master_sk_to_pool_sk,
    master_sk_to_farmer_sk,
    master_sk_to_wallet_sk,
)
from src.util.ints import uint32
from src.consensus.coinbase import create_puzzlehash_for_pk


keychain: Keychain = Keychain()
mnemonic_option = click.option("--mnemonic", "-m", help="Enter mnemonic you want to use", nargs=24)
private_key_option = click.option("--key", "-k", help="Enter the raw private key in hex")
hd_path_option = click.option("--hd_path", "-t",  help="Enter the HD path in the form 'm/12381/8444/n/n'")
signature_option = click.option("--signature", "-s", help="Enter the signature in hex", required=True)
public_key_option = click.option("--public_key", "-p", help="Enter the pk in hex", required=True)


def message_option(required=False):
    return click.option(
        "--message",
        "-d",
        help="Enter the message to sign in UTF-8",
        required=required
    )


def fingerprint_option(required=False):
    return click.option(
        "--fingerprint",
        "-f",
        help="Enter the fingerprint of the key you want to use",
        required=required
    )


@click.command("generate-and-print")
def generate_and_print():
    """
    Generates a seed for a private key, and prints the mnemonic to the terminal.
    """

    mnemonic = generate_mnemonic()
    click.echo("Generating private key. Mnemonic (24 secret words):")
    click.echo(mnemonic)
    click.echo(
        "Note that this key has not been added to the keychain. Run chia keys add_seed -m [MNEMONICS] to add"
    )
    return mnemonic


@click.command()
@default_options()
def generate(state):
    """Generate and add a key to the keychain."""
    generate_and_add()
    check_keys(state.root_path)


def generate_and_add():
    """Generate a seed for a private key, print the mnemonic to the terminal,
    and add the key to the keyring."""
    mnemonic = generate_mnemonic()
    click.echo("Generating private key.")
    add_private_key_seed(mnemonic)


@click.command()
@mnemonic_option
@default_options()
def add(state, mnemonic):
    """Add a private key through mnemonic."""
    add_private_key_seed(mnemonic)
    check_keys(state.root_path)


def add_private_key_seed(mnemonic):
    """Add a private key seed to the keyring, with the given mnemonic."""

    try:
        passphrase = ""
        sk = keychain.add_private_key(mnemonic, passphrase)
        fingerprint = sk.get_g1().get_fingerprint()
        click.echo(
            f"Added private key with public key fingerprint {fingerprint} and mnemonic"
        )
        click.echo(mnemonic)

    except ValueError as e:
        click.echo(e)
        return


@click.command("show")
def show_all_keys():
    """Print all keys and mnemonics (if available)."""

    private_keys = keychain.get_all_private_keys()
    if not private_keys:
        click.echo("There are no saved private keys.")
        return

    click.echo("Showing all private keys:")
    for sk, seed in private_keys:
        click.echo("\nFingerprint: {}".format(sk.get_g1().get_fingerprint()))
        click.echo("Master public key (m): {}".format(sk.get_g1()))
        click.echo("Master private key (m): {}".format(bytes(sk).hex()))
        click.echo(
            "Farmer public key (m/12381/8444/0/0):: {}".format(
            master_sk_to_farmer_sk(sk).get_g1(),
        ))

        click.echo("Pool public key (m/12381/8444/1/0): {}".format(master_sk_to_pool_sk(sk).get_g1()))
        click.echo(
            "First wallet key (m/12381/8444/2/0): {}".format(master_sk_to_wallet_sk(sk, uint32(0)).get_g1())
        )
        click.echo(
            "First wallet address: {}".format(
            encode_puzzle_hash(
                create_puzzlehash_for_pk(master_sk_to_wallet_sk(sk, uint32(0)).get_g1())
            ))
        )
        assert seed is not None
        mnemonic = bytes_to_mnemonic(seed)
        click.echo("  Mnemonic seed (24 secret words):\n{}".format(mnemonic))


@click.command()
@fingerprint_option(required=True)
def delete(fingerprint):
    """Delete a key by it's public key fingerprint (which is an int)."""
    click.echo(f"Deleting private_key with fingerprint {fingerprint}")
    keychain.delete_key_by_fingerprint(fingerprint)


@click.command()
def delete_all():
    """Delete all private keys in the keychain."""
    keychain.delete_all_keys()


@click.command()
@message_option(required=True)
@fingerprint_option()
@hd_path_option
def sign(message, fingerprint, hd_path):
    """Sign a message with a private key."""

    if fingerprint is None or hd_path is None:
        click.echo("Please specify the fingerprint argument -f and hd_path argument -t")
        quit()

    k = Keychain()
    private_keys = k.get_all_private_keys()

    path: List[uint32] = [uint32(int(i)) for i in hd_path.split("/") if i != "m"]
    for sk, _ in private_keys:
        if sk.get_g1().get_fingerprint() == fingerprint:
            for c in path:
                sk = AugSchemeMPL.derive_child_sk(sk, c)
            click.echo("Public key:", sk.get_g1())
            click.echo("Signature:", AugSchemeMPL.sign(sk, bytes(message, "utf-8")))
            return
    click.echo(f"Fingerprint {fingerprint} not found in keychain")


@click.command()
@message_option(required=True)
@public_key_option
@signature_option
def verify(message, public_key, signature):
    """Verify a signature with a pk."""

    message = bytes(message, "utf-8")
    public_key = G1Element.from_bytes(bytes.fromhex(public_key))
    signature = G2Element.from_bytes(bytes.fromhex(signature))
    click.echo(AugSchemeMPL.verify(public_key, message, signature))


@click.group()
def keys():
    """Chia keys commands."""
    pass


keys.add_command(generate)
keys.add_command(show_all_keys)
keys.add_command(add)
keys.add_command(delete)
keys.add_command(delete_all)
keys.add_command(generate_and_print)
keys.add_command(sign)
keys.add_command(verify)
