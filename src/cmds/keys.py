from pathlib import Path
from typing import List
import click

from blspy import AugSchemeMPL, G1Element, G2Element

from src.cmds.init import check_keys
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
public_key_option = click.option("--public_key", "-p", help="Enter the pk in hex",)
signature_option = click.option("--signature", "-s", help="Enter the signature in hex")


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


@click.group
def keys():
    pass


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


@click.command("generate")
def generate_and_add():
    """
    Generates a seed for a private key, prints the mnemonic to the terminal, and adds the key to the keyring.
    """

    mnemonic = generate_mnemonic()
    click.echo("Generating private key.")
    add_private_key_seed(mnemonic)


@click.command("add")
@mnemonic_option
def add_private_key_seed(mnemonic):
    """
    Add a private key seed to the keyring, with the given mnemonic.
    """

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
    """
    Prints all keys and mnemonics (if available).
    """

    private_keys = keychain.get_all_private_keys()
    if len(private_keys) == 0:
        click.echo("There are no saved private keys.")
        return
    click.echo("Showing all private keys:")
    for sk, seed in private_keys:
        click.echo("\nFingerprint:", sk.get_g1().get_fingerprint())
        click.echo("Master public key (m):", sk.get_g1())
        click.echo("Master private key (m):", bytes(sk).hex())
        click.echo(
            "Farmer public key (m/12381/8444/0/0)::",
            master_sk_to_farmer_sk(sk).get_g1(),
        )
        click.echo("Pool public key (m/12381/8444/1/0):", master_sk_to_pool_sk(sk).get_g1())
        click.echo(
            "First wallet key (m/12381/8444/2/0):",
            master_sk_to_wallet_sk(sk, uint32(0)).get_g1(),
        )
        click.echo(
            "First wallet address:",
            encode_puzzle_hash(
                create_puzzlehash_for_pk(master_sk_to_wallet_sk(sk, uint32(0)).get_g1())
            ),
        )
        assert seed is not None
        mnemonic = bytes_to_mnemonic(seed)
        click.echo("  Mnemonic seed (24 secret words):")
        click.echo(mnemonic)


@click.command()
@fingerprint_option(required=True)
def delete(fingerprint):
    """
    Delete a key by it's public key fingerprint (which is an int).
    """
    click.echo(f"Deleting private_key with fingerprint {fingerprint}")
    keychain.delete_key_by_fingerprint(fingerprint)


@click.command()
@message_option(required=True)
@fingerprint_option()
@hd_path_option
def sign(message, fingerprint, hd_path):
    if fingerprint is None or hd_path is None:
        click.echo("Please specify the fingerprint argument -f and hd_path argument -t")
        quit()

    k = Keychain()
    private_keys = k.get_all_private_keys()

    fingerprint = fingerprint
    assert fingerprint is not None
    hd_path = hd_path
    assert hd_path is not None
    path: List[uint32] = [uint32(int(i)) for i in hd_path.split("/") if i != "m"]
    for sk, _ in private_keys:
        if sk.get_g1().get_fingerprint() == fingerprint:
            for c in path:
                sk = AugSchemeMPL.derive_child_sk(sk, c)
            click.echo("Public key:", sk.get_g1())
            click.echo("Signature:", AugSchemeMPL.sign(sk, bytes(message, "utf-8")))
            return
    click.echo(f"Fingerprint {fingerprint} not found in keychain")


@message_option()
def verify(args):
    if args.message is None:
        click.echo("Please specify the message argument -d")
        quit()
    if args.public_key is None:
        click.echo("Please specify the public_key argument -p")
        quit()
    if args.signature is None:
        print("Please specify the signature argument -s")
        quit()
    assert args.message is not None
    assert args.public_key is not None
    assert args.signature is not None
    message = bytes(args.message, "utf-8")
    public_key = G1Element.from_bytes(bytes.fromhex(args.public_key))
    signature = G2Element.from_bytes(bytes.fromhex(args.signature))
    print(AugSchemeMPL.verify(public_key, message, signature))


def handler(args, parser):
    if args.command is None or len(args.command) < 1:
        help_message()
        parser.exit(1)

    root_path: Path = args.root_path
    if not root_path.is_dir():
        raise RuntimeError(
            "Please initialize (or migrate) your config directory with chia init."
        )

    command = args.command
    if command not in command_list:
        help_message()
        parser.exit(1)

    if command == "generate":
        generate_and_add()
        check_keys(root_path)
    elif command == "show":
        show_all_keys()
    elif command == "add":
        add_private_key_seed(" ".join(args.mnemonic))
        check_keys(root_path)
    elif command == "delete":
        delete(args)
        check_keys(root_path)
    elif command == "delete_all":
        keychain.delete_all_keys()
    if command == "generate_and_print":
        generate_and_print()
    if command == "sign":
        sign(args)
    if command == "verify":
        verify(args)
