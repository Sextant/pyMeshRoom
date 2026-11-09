"""Python client for pyMeshRoom's KaaS API (KISS radio as an API service).

KaasClient streams every packet the server's radio hears and sends, and sends raw packets. Node adds what a MeshCore
chat node does on top: adverts, contacts, DMs, channels and joining rooms, with the crypto done here."""
from .client import KaasClient, RequestError, SendResult
from .crypto import Identity, channel_hash, hashtag_channel_key
from .node import Channel, Contact, LoginFailed, Node, Room
from .packet import Packet
from .ws import Closed, HandshakeError

__all__ = ["KaasClient", "RequestError", "SendResult", "Identity", "Node", "Contact", "Channel", "Room", "LoginFailed", "Packet",
           "Closed", "HandshakeError", "channel_hash", "hashtag_channel_key"]
__version__ = "0.1.0"
