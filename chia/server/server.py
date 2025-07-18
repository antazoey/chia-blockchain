from __future__ import annotations

import asyncio
import logging
import ssl
import time
import traceback
from collections.abc import Awaitable
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_network
from pathlib import Path
from typing import Any, Callable, Optional, Union, cast

from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    ServerDisconnectedError,
    WSCloseCode,
    client_exceptions,
    web,
)
from chia_rs.sized_bytes import bytes32
from chia_rs.sized_ints import uint16
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from typing_extensions import final

from chia.protocols.outbound_message import Message, NodeType
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.protocols.protocol_state_machine import message_requires_reply
from chia.protocols.protocol_timing import INVALID_PROTOCOL_BAN_SECONDS
from chia.server.api_protocol import ApiProtocol
from chia.server.introducer_peers import IntroducerPeers
from chia.server.ssl_context import private_ssl_paths, public_ssl_paths
from chia.server.ws_connection import ConnectionCallback, WSChiaConnection
from chia.ssl.ssl_check import verify_ssl_certs_and_keys
from chia.types.peer_info import PeerInfo
from chia.util.errors import Err, ProtocolError
from chia.util.network import WebServer, is_in_network, is_localhost, is_trusted_peer
from chia.util.streamable import Streamable
from chia.util.task_referencer import create_referenced_task

max_message_size = 50 * 1024 * 1024  # 50MB


def ssl_context_for_server(
    ca_cert: Path,
    ca_key: Path,
    cert_path: Path,
    key_path: Path,
    *,
    check_permissions: bool = True,
    log: Optional[logging.Logger] = None,
) -> ssl.SSLContext:
    if check_permissions:
        verify_ssl_certs_and_keys([ca_cert, cert_path], [ca_key, key_path], log)

    ssl_context = ssl._create_unverified_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=str(ca_cert))  # noqa: S323
    ssl_context.check_hostname = False
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-SHA384:"
        "ECDHE-RSA-AES256-SHA384:"
        "ECDHE-ECDSA-AES128-SHA256:"
        "ECDHE-RSA-AES128-SHA256"
    )
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    return ssl_context


def ssl_context_for_root(
    ca_cert_file: str, *, check_permissions: bool = True, log: Optional[logging.Logger] = None
) -> ssl.SSLContext:
    if check_permissions:
        verify_ssl_certs_and_keys([Path(ca_cert_file)], [], log)

    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_cert_file)
    return ssl_context


def ssl_context_for_client(
    ca_cert: Path,
    ca_key: Path,
    cert_path: Path,
    key_path: Path,
    *,
    check_permissions: bool = True,
    log: Optional[logging.Logger] = None,
) -> ssl.SSLContext:
    if check_permissions:
        verify_ssl_certs_and_keys([ca_cert, cert_path], [ca_key, key_path], log)

    ssl_context = ssl._create_unverified_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert))  # noqa: S323
    ssl_context.check_hostname = False
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    return ssl_context


def calculate_node_id(cert_path: Path) -> bytes32:
    pem_cert = x509.load_pem_x509_certificate(cert_path.read_bytes(), default_backend())
    der_cert_bytes = pem_cert.public_bytes(encoding=serialization.Encoding.DER)
    der_cert = x509.load_der_x509_certificate(der_cert_bytes, default_backend())
    return bytes32(der_cert.fingerprint(hashes.SHA256()))


@final
@dataclass
class ChiaServer:
    _port: Optional[int]
    _local_type: NodeType
    _local_capabilities_for_handshake: list[tuple[uint16, str]]
    _ping_interval: int
    _network_id: str
    _inbound_rate_limit_percent: int
    _outbound_rate_limit_percent: int
    api: ApiProtocol
    node: Any
    root_path: Path
    config: dict[str, Any]
    log: logging.Logger
    ssl_context: ssl.SSLContext
    ssl_client_context: ssl.SSLContext
    node_id: bytes32
    exempt_peer_networks: list[Union[IPv4Network, IPv6Network]]
    class_for_type: dict[NodeType, type[ApiProtocol]]
    all_connections: dict[bytes32, WSChiaConnection] = field(default_factory=dict)
    on_connect: Optional[ConnectionCallback] = None
    shut_down_event: asyncio.Event = field(default_factory=asyncio.Event)
    introducer_peers: Optional[IntroducerPeers] = None
    gc_task: Optional[asyncio.Task[None]] = None
    webserver: Optional[WebServer] = None
    connection_close_task: Optional[asyncio.Task[None]] = None
    received_message_callback: Optional[ConnectionCallback] = None
    banned_peers: dict[str, float] = field(default_factory=dict)
    invalid_protocol_ban_seconds: int = INVALID_PROTOCOL_BAN_SECONDS

    @classmethod
    def create(
        cls,
        port: Optional[int],
        node: Any,
        api: ApiProtocol,
        local_type: NodeType,
        ping_interval: int,
        network_id: str,
        inbound_rate_limit_percent: int,
        outbound_rate_limit_percent: int,
        capabilities: list[tuple[uint16, str]],
        root_path: Path,
        config: dict[str, Any],
        private_ca_crt_key: tuple[Path, Path],
        chia_ca_crt_key: tuple[Path, Path],
        class_for_type: dict[NodeType, type[ApiProtocol]],
        name: str = __name__,
    ) -> ChiaServer:
        log = logging.getLogger(name)
        log.info("Service capabilities: %s", capabilities)

        ca_private_crt_path, ca_private_key_path = private_ca_crt_key
        chia_ca_crt_path, chia_ca_key_path = chia_ca_crt_key

        private_cert_path, private_key_path = None, None
        public_cert_path, public_key_path = None, None

        authenticated_client_types = {NodeType.HARVESTER}
        authenticated_server_types = {NodeType.HARVESTER, NodeType.FARMER, NodeType.WALLET, NodeType.DATA_LAYER}

        if local_type in authenticated_client_types:
            # Authenticated clients
            private_cert_path, private_key_path = private_ssl_paths(root_path, config)
            ssl_client_context = ssl_context_for_client(
                ca_cert=ca_private_crt_path,
                ca_key=ca_private_key_path,
                cert_path=private_cert_path,
                key_path=private_key_path,
            )
        else:
            # Public clients
            public_cert_path, public_key_path = public_ssl_paths(root_path, config)
            ssl_client_context = ssl_context_for_client(
                ca_cert=chia_ca_crt_path,
                ca_key=chia_ca_key_path,
                cert_path=public_cert_path,
                key_path=public_key_path,
            )

        if local_type in authenticated_server_types:
            # Authenticated servers
            private_cert_path, private_key_path = private_ssl_paths(root_path, config)
            ssl_context = ssl_context_for_server(
                ca_cert=ca_private_crt_path,
                ca_key=ca_private_key_path,
                cert_path=private_cert_path,
                key_path=private_key_path,
                log=log,
            )
        else:
            # Public servers
            public_cert_path, public_key_path = public_ssl_paths(root_path, config)
            ssl_context = ssl_context_for_server(
                ca_cert=chia_ca_crt_path,
                ca_key=chia_ca_key_path,
                cert_path=public_cert_path,
                key_path=public_key_path,
                log=log,
            )

        node_id_cert_path = private_cert_path if public_cert_path is None else public_cert_path
        assert node_id_cert_path is not None

        return cls(
            _port=port,
            _local_type=local_type,
            _local_capabilities_for_handshake=capabilities,
            _ping_interval=ping_interval,
            _network_id=network_id,
            _inbound_rate_limit_percent=inbound_rate_limit_percent,
            _outbound_rate_limit_percent=outbound_rate_limit_percent,
            log=log,
            api=api,
            node=node,
            root_path=root_path,
            config=config,
            ssl_context=ssl_context,
            ssl_client_context=ssl_client_context,
            node_id=calculate_node_id(node_id_cert_path),
            exempt_peer_networks=[ip_network(net, strict=False) for net in config.get("exempt_peer_networks", [])],
            introducer_peers=IntroducerPeers() if local_type is NodeType.INTRODUCER else None,
            class_for_type=class_for_type,
        )

    def set_received_message_callback(self, callback: ConnectionCallback) -> None:
        self.received_message_callback = callback

    async def garbage_collect_connections_task(self) -> None:
        """
        Periodically checks for connections with no activity (have not sent us any data), and removes them,
        to allow room for other peers.
        """
        is_crawler = getattr(self.node, "crawl", None)
        while True:
            await asyncio.sleep(600 if is_crawler is None else 2)
            to_remove: list[WSChiaConnection] = []
            for connection in self.all_connections.values():
                if connection.closed:
                    to_remove.append(connection)
                elif (
                    self._local_type in {NodeType.FULL_NODE, NodeType.WALLET}
                ) and connection.connection_type == NodeType.FULL_NODE:
                    if is_crawler is not None:
                        if time.time() - connection.creation_time > 5:
                            to_remove.append(connection)
                    else:
                        if time.time() - connection.last_message_time > 1800:
                            to_remove.append(connection)
            for connection in to_remove:
                self.log.debug(f"Garbage collecting connection {connection.peer_info.host} due to inactivity")
                if connection.closed:
                    self.all_connections.pop(connection.peer_node_id)
                else:
                    await connection.close()

            # Also garbage collect banned_peers dict
            to_remove_ban = []
            for peer_ip, ban_until_time in self.banned_peers.items():
                if time.time() > ban_until_time:
                    to_remove_ban.append(peer_ip)
            for peer_ip in to_remove_ban:
                del self.banned_peers[peer_ip]

    async def start(
        self,
        prefer_ipv6: bool,
        on_connect: Optional[ConnectionCallback] = None,
    ) -> None:
        if self.webserver is not None:
            raise RuntimeError("ChiaServer already started")
        if self.gc_task is None:
            self.gc_task = create_referenced_task(self.garbage_collect_connections_task())

        if self._port is not None:
            self.on_connect = on_connect
            self.webserver = await WebServer.create(
                hostname="",
                port=self.get_port(),
                routes=[web.get("/ws", self.incoming_connection)],
                ssl_context=self.ssl_context,
                prefer_ipv6=prefer_ipv6,
                logger=self.log,
            )
            self._port = int(self.webserver.listen_port)
            self.log.info(f"Started listening on port: {self._port}")

    async def incoming_connection(self, request: web.Request) -> web.StreamResponse:
        if getattr(self.node, "crawl", None) is not None:
            raise web.HTTPForbidden(reason="incoming connections not allowed for crawler")
        if request.remote is None:
            raise web.HTTPInternalServerError(reason=f"remote is None for request {request}")
        if request.remote in self.banned_peers and time.time() < self.banned_peers[request.remote]:
            reason = f"Peer {request.remote} is banned, refusing connection"
            self.log.warning(reason)
            raise web.HTTPForbidden(reason=reason)
        ws = web.WebSocketResponse(max_msg_size=max_message_size)
        await ws.prepare(request)
        ssl_object = request.get_extra_info("ssl_object")
        if ssl_object is None:
            reason = f"ssl_object is None for request {request}"
            self.log.warning(reason)
            raise web.HTTPInternalServerError(reason=reason)
        cert_bytes = ssl_object.getpeercert(True)
        der_cert = x509.load_der_x509_certificate(cert_bytes)
        peer_id = bytes32(der_cert.fingerprint(hashes.SHA256()))
        if peer_id == self.node_id:
            return ws
        connection: Optional[WSChiaConnection] = None
        try:
            connection = WSChiaConnection.create(
                local_type=self._local_type,
                ws=ws,
                api=self.api,
                server_port=self.get_port(),
                log=self.log,
                is_outbound=False,
                received_message_callback=self.received_message_callback,
                close_callback=self.connection_closed,
                peer_id=peer_id,
                inbound_rate_limit_percent=self._inbound_rate_limit_percent,
                outbound_rate_limit_percent=self._outbound_rate_limit_percent,
                local_capabilities_for_handshake=self._local_capabilities_for_handshake,
                class_for_type=self.class_for_type,
            )
            await connection.perform_handshake(self._network_id, self.get_port(), self._local_type)
            assert connection.connection_type is not None, "handshake failed to set connection type, still None"

            # Limit inbound connections to config's specifications.
            if not self.accept_inbound_connections(connection.connection_type) and not is_in_network(
                connection.peer_info.host, self.exempt_peer_networks
            ):
                self.log.info(
                    f"Not accepting inbound connection: {connection.get_peer_logging()}.Inbound limit reached."
                )
                await connection.close()
            else:
                await self.connection_added(connection, self.on_connect)
                if self.introducer_peers is not None and connection.connection_type is NodeType.FULL_NODE:
                    self.introducer_peers.add(connection.get_peer_info())
        except ProtocolError as e:
            if connection is not None:
                await connection.close(self.invalid_protocol_ban_seconds, WSCloseCode.PROTOCOL_ERROR, e.code)
            if e.code == Err.INVALID_HANDSHAKE:
                self.log.warning("Invalid handshake with peer. Maybe the peer is running old software.")
            elif e.code == Err.INCOMPATIBLE_NETWORK_ID:
                self.log.warning("Incompatible network ID. Maybe the peer is on another network")
            else:
                error_stack = traceback.format_exc()
                self.log.error(f"Exception {e}, exception Stack: {error_stack}")
        except ValueError as e:
            if connection is not None:
                await connection.close(self.invalid_protocol_ban_seconds, WSCloseCode.PROTOCOL_ERROR, Err.UNKNOWN)
            self.log.warning(f"{e} - closing connection")
        except Exception as e:
            if connection is not None:
                await connection.close(ws_close_code=WSCloseCode.PROTOCOL_ERROR, error=Err.UNKNOWN)
            error_stack = traceback.format_exc()
            self.log.error(f"Exception {e}, exception Stack: {error_stack}")

        if connection is not None:
            await connection.wait_until_closed()

        return ws

    async def connection_added(
        self, connection: WSChiaConnection, on_connect: Optional[ConnectionCallback] = None
    ) -> None:
        # If we already had a connection to this peer_id, close the old one. This is secure because peer_ids are based
        # on TLS public keys
        if connection.closed:
            self.log.debug(f"ignoring unexpected request to add closed connection {connection.peer_info.host} ")
            return

        if connection.peer_node_id in self.all_connections:
            con = self.all_connections[connection.peer_node_id]
            await con.close()
        self.all_connections[connection.peer_node_id] = connection
        if connection.connection_type is not None:
            if on_connect is not None:
                await on_connect(connection)
        else:
            self.log.error(f"Invalid connection type for connection {connection}")

    def is_duplicate_or_self_connection(self, target_node: PeerInfo) -> bool:
        if is_localhost(target_node.host) and target_node.port == self._port:
            # Don't connect to self
            self.log.debug(f"Not connecting to {target_node}")
            return True
        for connection in self.all_connections.values():
            if connection.peer_info.host == target_node.host and connection.peer_server_port == target_node.port:
                self.log.debug(f"Not connecting to {target_node}, duplicate connection")
                return True
        return False

    async def start_client(
        self,
        target_node: PeerInfo,
        on_connect: Optional[ConnectionCallback] = None,
        is_feeler: bool = False,
    ) -> bool:
        """
        Tries to connect to the target node, adding one connection into the pipeline, if successful.
        An on connect method can also be specified, and this will be saved into the instance variables.
        """
        if self.is_duplicate_or_self_connection(target_node):
            self.log.warning(f"cannot connect to {target_node.host}, duplicate/self connection")
            return False

        if target_node.host in self.banned_peers and time.time() < self.banned_peers[target_node.host]:
            self.log.warning(f"Peer {target_node.host} is still banned, not connecting to it")
            return False

        session = None
        connection: Optional[WSChiaConnection] = None
        try:
            # Crawler/DNS introducer usually uses a lower timeout than the default
            timeout_value = float(self.config.get("peer_connect_timeout", 30))
            timeout = ClientTimeout(total=timeout_value)
            session = ClientSession(timeout=timeout)
            ip = f"[{target_node.ip}]" if target_node.ip.is_v6 else f"{target_node.ip}"
            url = f"wss://{ip}:{target_node.port}/ws"
            self.log.debug(f"Connecting: {url}, Peer info: {target_node}")
            try:
                ws = await session.ws_connect(
                    url,
                    autoclose=True,
                    autoping=True,
                    heartbeat=60,
                    ssl=self.ssl_client_context,
                    max_msg_size=max_message_size,
                )
            except ServerDisconnectedError:
                self.log.debug(f"Server disconnected error connecting to {url}. Perhaps we are banned by the peer.")
                return False
            except ClientResponseError as e:
                self.log.warning(f"Connection failed to {url}. Error: {e}")
                return False
            except asyncio.TimeoutError:
                self.log.debug(f"Timeout error connecting to {url}")
                return False
            if ws is None:
                self.log.warning(f"Connection failed to {url}. ws was None")
                return False

            ssl_object = ws.get_extra_info("ssl_object")
            if ssl_object is None:
                raise ValueError(f"ssl_object is None for {ws}")
            cert_bytes = ssl_object.getpeercert(True)
            der_cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
            peer_id = bytes32(der_cert.fingerprint(hashes.SHA256()))
            if peer_id == self.node_id:
                self.log.info(f"Connected to a node with the same peer ID, disconnecting: {target_node} {peer_id}")
                return False

            server_port: uint16
            try:
                server_port = self.get_port()
            except ValueError:
                server_port = uint16(0)

            connection = WSChiaConnection.create(
                local_type=self._local_type,
                ws=ws,
                api=self.api,
                server_port=server_port,
                log=self.log,
                is_outbound=True,
                received_message_callback=self.received_message_callback,
                close_callback=self.connection_closed,
                peer_id=peer_id,
                inbound_rate_limit_percent=self._inbound_rate_limit_percent,
                outbound_rate_limit_percent=self._outbound_rate_limit_percent,
                local_capabilities_for_handshake=self._local_capabilities_for_handshake,
                class_for_type=self.class_for_type,
                session=session,
            )
            await connection.perform_handshake(self._network_id, server_port, self._local_type)
            await self.connection_added(connection, on_connect)
            # the session has been adopted by the connection, don't close it at
            # the end of the function
            session = None
            connection_type_str = ""
            if connection.connection_type is not None:
                connection_type_str = connection.connection_type.name.lower()
            if not is_feeler:
                self.log.info(f"Connected with {connection_type_str} {target_node}")
            else:
                self.log.debug(f"Successful feeler connection with {connection_type_str} {target_node}")
                create_referenced_task(connection.close(), known_unreferenced=True)
            return True
        except client_exceptions.ClientConnectorError as e:
            if is_feeler:
                self.log.debug(f"Feeler connection error. {e}")
            else:
                self.log.info(f"{e}")
        except ProtocolError as e:
            if connection is not None:
                await connection.close(self.invalid_protocol_ban_seconds, WSCloseCode.PROTOCOL_ERROR, e.code)
            if e.code == Err.INVALID_HANDSHAKE:
                self.log.warning(
                    f"Invalid handshake with peer {target_node}{' during feeler connection' if is_feeler else ''}"
                    f". Maybe the peer is running old software."
                )
            elif e.code == Err.INCOMPATIBLE_NETWORK_ID:
                self.log.warning(
                    f"Incompatible network ID{' during feeler connection' if is_feeler else ''}"
                    f". Maybe the peer is on another network"
                )
            elif e.code == Err.SELF_CONNECTION:
                pass
            else:
                error_stack = traceback.format_exc()
                self.log.error(
                    f"{'Feeler connection ' if is_feeler else ''}Exception {e}, exception Stack: {error_stack}"
                )
        except Exception as e:
            if connection is not None:
                await connection.close(self.invalid_protocol_ban_seconds, WSCloseCode.PROTOCOL_ERROR, Err.UNKNOWN)
            error_stack = traceback.format_exc()
            self.log.error(f"{'Feeler connection ' if is_feeler else ''}Exception {e}, exception Stack: {error_stack}")
        finally:
            if session is not None:
                await session.close()

        return False

    async def connection_closed(
        self, connection: WSChiaConnection, ban_time: int, closed_connection: bool = False
    ) -> None:
        # closed_connection is true if the callback is being called with a connection that was previously closed
        # in this case we still want to do the banning logic and remove the connection from the list
        # but the other cleanup should already have been done so we skip that

        if is_localhost(connection.peer_info.host) and ban_time != 0:
            self.log.warning(f"Trying to ban localhost for {ban_time}, but will not ban")
            ban_time = 0
        if ban_time > 0:
            ban_until: float = time.time() + ban_time
            self.log.warning(f"Banning {connection.peer_info.host} for {ban_time} seconds")
            if connection.peer_info.host in self.banned_peers:
                self.banned_peers[connection.peer_info.host] = max(
                    ban_until, self.banned_peers[connection.peer_info.host]
                )
            else:
                self.banned_peers[connection.peer_info.host] = ban_until

        present_connection = self.all_connections.get(connection.peer_node_id)
        if present_connection is connection:
            self.all_connections.pop(connection.peer_node_id)

        if not closed_connection:
            self.log.info(f"Connection closed: {connection.peer_info.host}, node id: {connection.peer_node_id}")

            if connection.connection_type is None:
                # This means the handshake was never finished with this peer
                self.log.debug(
                    f"Invalid connection type for connection {connection.peer_info.host},"
                    f" while closing. Handshake never finished."
                )
            connection.cancel_tasks()
            on_disconnect = getattr(self.node, "on_disconnect", None)
            if on_disconnect is not None:
                await on_disconnect(connection)

    async def validate_broadcast_message_type(self, messages: list[Message], node_type: NodeType) -> None:
        for message in messages:
            if message_requires_reply(ProtocolMessageTypes(message.type)):
                # Internal protocol logic error - we will raise, blocking messages to all peers
                self.log.error(f"Attempt to broadcast message requiring protocol response: {message.type}")
                for _, connection in self.all_connections.items():
                    if connection.connection_type is node_type:
                        await connection.close(
                            ban_time=self.invalid_protocol_ban_seconds,
                            ws_close_code=WSCloseCode.INTERNAL_ERROR,
                            error=Err.INTERNAL_PROTOCOL_ERROR,
                        )
                raise ProtocolError(Err.INTERNAL_PROTOCOL_ERROR, [message.type])

    async def send_to_all(
        self,
        messages: list[Message],
        node_type: NodeType,
        exclude: Optional[bytes32] = None,
    ) -> None:
        await self.validate_broadcast_message_type(messages, node_type)
        for _, connection in self.all_connections.items():
            if connection.connection_type is node_type and connection.peer_node_id != exclude:
                for message in messages:
                    await connection.send_message(message)

    async def send_to_all_if(
        self,
        messages: list[Message],
        node_type: NodeType,
        predicate: Callable[[WSChiaConnection], bool],
        exclude: Optional[bytes32] = None,
    ) -> None:
        await self.validate_broadcast_message_type(messages, node_type)
        for _, connection in self.all_connections.items():
            if connection.connection_type is node_type and connection.peer_node_id != exclude and predicate(connection):
                for message in messages:
                    await connection.send_message(message)

    async def send_to_specific(self, messages: list[Message], node_id: bytes32) -> None:
        if node_id in self.all_connections:
            connection = self.all_connections[node_id]
            for message in messages:
                await connection.send_message(message)

    async def call_api_of_specific(
        self, request_method: Callable[..., Awaitable[Optional[Message]]], message_data: Streamable, node_id: bytes32
    ) -> Optional[Any]:
        if node_id in self.all_connections:
            connection = self.all_connections[node_id]
            return await connection.call_api(request_method, message_data)

        return None

    def get_connections(
        self, node_type: Optional[NodeType] = None, *, outbound: Optional[bool] = None
    ) -> list[WSChiaConnection]:
        result = []
        for _, connection in self.all_connections.items():
            node_type_match = node_type is None or connection.connection_type == node_type
            outbound_match = outbound is None or connection.is_outbound == outbound
            if node_type_match and outbound_match:
                result.append(connection)
        return result

    async def close_all_connections(self) -> None:
        for connection in self.all_connections.copy().values():
            try:
                await connection.close()
            except Exception as e:
                self.log.error(f"Exception while closing connection {e}")

    def close_all(self) -> None:
        self.connection_close_task = create_referenced_task(self.close_all_connections())
        if self.webserver is not None:
            self.webserver.close()

        self.shut_down_event.set()
        if self.gc_task is not None:
            self.gc_task.cancel()
            self.gc_task = None

    async def await_closed(self) -> None:
        self.log.debug("Await Closed")
        await self.shut_down_event.wait()
        if self.connection_close_task is not None:
            await self.connection_close_task
        if self.webserver is not None:
            await self.webserver.await_closed()
            self.webserver = None

    async def get_peer_info(self) -> Optional[PeerInfo]:
        ip = None

        try:
            port = self.get_port()
        except ValueError:
            return None  # server doesn't have a local port, just return None here

        # Use chia's service first.
        try:
            timeout = ClientTimeout(total=15)
            async with ClientSession(timeout=timeout) as session:
                async with session.get("https://ip.chia.net/") as resp:
                    if resp.status == 200:
                        ip = str(await resp.text())
                        ip = ip.rstrip()
        except Exception:
            ip = None

        # Fallback to `checkip` from amazon.
        if ip is None:
            try:
                timeout = ClientTimeout(total=15)
                async with ClientSession(timeout=timeout) as session:
                    async with session.get("https://checkip.amazonaws.com/") as resp:
                        if resp.status == 200:
                            ip = str(await resp.text())
                            ip = ip.rstrip()
            except Exception:
                ip = None
        if ip is None:
            return None
        try:
            return PeerInfo(ip, uint16(port))
        except ValueError:
            return None

    def get_port(self) -> uint16:
        if self._port is None:
            raise ValueError("Port not set")
        return uint16(self._port)

    def accept_inbound_connections(self, node_type: NodeType) -> bool:
        if not self._local_type == NodeType.FULL_NODE:
            return True
        inbound_count = len(self.get_connections(node_type, outbound=False))
        if node_type == NodeType.FULL_NODE:
            return inbound_count < cast(int, self.config.get("target_peer_count", 40)) - cast(
                int, self.config.get("target_outbound_peer_count", 8)
            )
        if node_type == NodeType.WALLET:
            return inbound_count < cast(int, self.config.get("max_inbound_wallet", 20))
        if node_type == NodeType.FARMER:
            return inbound_count < cast(int, self.config.get("max_inbound_farmer", 10))
        if node_type == NodeType.TIMELORD:
            return inbound_count < cast(int, self.config.get("max_inbound_timelord", 5))
        return True

    def is_trusted_peer(self, peer: WSChiaConnection, trusted_peers: dict[str, Any]) -> bool:
        return is_trusted_peer(
            host=peer.peer_info.host,
            node_id=peer.peer_node_id,
            trusted_peers=trusted_peers,
            trusted_cidrs=self.config.get("trusted_cidrs", []),
            testing=self.config.get("testing", False),
        )

    def set_capabilities(self, capabilities: list[tuple[uint16, str]]) -> None:
        self._local_capabilities_for_handshake = capabilities
