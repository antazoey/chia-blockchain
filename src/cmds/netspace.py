import aiohttp
import aiohttp.client_exceptions
import asyncio
import time
from time import struct_time, localtime
import datetime
import click
from src.util.config import load_config
from src.util.default_root import DEFAULT_ROOT_PATH

from src.rpc.full_node_rpc_client import FullNodeRpcClient


data_block_height_option = click.option(
    "--delta-block-height",
    "-d",
    help="Compare a block X blocks older.",
    default="24"
)

start_option = click.option(
    "--start",
    "-s",
    help="Newest block used to calculate estimated total network space. Defaults to LCA.",
    default=""
)

port_option = click.option(
    "--rpc-port",
    "-p",
    help="Set the port where the Full Node is hosting the RPC interface."
)


@click.command()
@data_block_height_option
@start_option
@port_option
def netspace(delta_block_height, start, rpc_port):
    return asyncio.run(netstorge_async(delta_block_height, start, rpc_port))


async def netstorge_async(delta_block_height, start, rpc_port):
    """
    Calculates the estimated space on the network given two block header hashes
    # TODO: add help on failure/no args
    """
    client = None
    try:
        config = load_config(DEFAULT_ROOT_PATH, "config.yaml")
        self_hostname = config["self_hostname"]
        if not rpc_port:
            rpc_port = config["full_node"]["rpc_port"]

        client = await FullNodeRpcClient.create(self_hostname, rpc_port)

        # print (args.blocks)
        if delta_block_height:
            # Get lca or newer block
            if not start:
                blockchain_state = await client.get_blockchain_state()
                newer_block_height = blockchain_state["lca"].data.height
            else:
                newer_block_height = int(start)  # Starting block height in args
            newer_block_header = await client.get_header_by_height(newer_block_height)
            older_block_height = newer_block_height - int(delta_block_height)
            older_block_header = await client.get_header_by_height(older_block_height)
            newer_block_header_hash = str(newer_block_header.get_hash())
            older_block_header_hash = str(older_block_header.get_hash())
            elapsed_time = (
                newer_block_header.data.timestamp - older_block_header.data.timestamp
            )
            newer_block_time_string = human_local_time(
                newer_block_header.data.timestamp
            )
            older_block_time_string = human_local_time(
                older_block_header.data.timestamp
            )
            time_delta = datetime.timedelta(seconds=elapsed_time)
            network_space_bytes_estimate = await client.get_network_space(
                newer_block_header_hash, older_block_header_hash
            )
            print(
                f"Older Block: {older_block_header.data.height}\n"
                f"Header Hash: 0x{older_block_header_hash}\n"
                f"Timestamp:   {older_block_time_string}\n"
                f"Weight:      {older_block_header.data.weight}\n"
                f"Total VDF\n"
                f"Iterations:  {older_block_header.data.total_iters}\n"
            )
            print(
                f"Newer Block: {newer_block_header.data.height}\n"
                f"Header Hash: 0x{newer_block_header_hash}\n"
                f"Timestamp:   {newer_block_time_string}\n"
                f"Weight:      {newer_block_header.data.weight}\n"
                f"Total VDF\n"
                f"Iterations:  {newer_block_header.data.total_iters}\n"
            )
            network_space_terrabytes_estimate = network_space_bytes_estimate / 1024 ** 4
            print(
                f"The elapsed time between blocks is reported as {time_delta}.\n"
                f"The network has an estimated {network_space_terrabytes_estimate:.2f}TiB"
            )

    except Exception as e:
        if isinstance(e, aiohttp.client_exceptions.ClientConnectorError):
            print(f"Connection error. Check if full node is running at {rpc_port}")
        else:
            print(f"Exception {e}")

    if client:
        client.close()
        await client.await_closed()


def human_local_time(timestamp):
    time_local = struct_time(localtime(timestamp))
    return time.strftime("%a %b %d %Y %T %Z", time_local)
