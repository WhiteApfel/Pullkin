import asyncio
import inspect
import json
import struct
from asyncio import StreamWriter, StreamReader
from base64 import urlsafe_b64decode
from binascii import hexlify
from typing import Optional, Callable, Union

import cryptography.hazmat.primitives.serialization as serialization
import http_ece
from cryptography.hazmat.backends import default_backend
from loguru import logger

from pullkin.client_base import PullkinBase
from pullkin.proto.mcs_pb2 import *

logger.disable("pullkin")


class AioPullkin(PullkinBase):
    def __init__(self):
        self.__reader: Optional[StreamReader] = None
        self.__writer: Optional[StreamWriter] = None
        self.credentials: dict = {}
        self.persistent_ids: list = []
        self.callback: Callable = None

    async def __open_connection(self):
        import ssl

        ssl_ctx = ssl.create_default_context()
        self.__reader, self.__writer = await asyncio.open_connection(
            self.PUSH_HOST, self.PUSH_PORT, ssl=ssl_ctx
        )
        logger.debug(f"Connected to SSL socket {self.PUSH_HOST}:{self.PUSH_PORT} with default ssl_context")

    async def __aioread(self, size):
        buf = b""
        while len(buf) < size:
            buf += await self.__reader.read(size - len(buf))
        return buf

    async def __aioread_varint32(self):
        res = 0
        shift = 0
        while True:
            (b,) = struct.unpack("B", await self.__aioread(1))
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    async def __aiosend(self, packet):
        logger.debug(f"Send")
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        logger.debug(f"Packet:\n'{packet}'")
        payload = packet.SerializeToString()
        buf = bytes(header) + self._encode_varint32(len(payload)) + payload
        logger.debug(f"HEX buffer:\n`{hexlify(buf)}`")
        self.__writer.write(buf)
        await self.__writer.drain()

    async def __aiorecv(self, first=False):
        logger.debug(f"Receive")
        if first:
            version, tag = struct.unpack("BB", await self.__aioread(2))
            logger.debug(f"Version {version}")
            if version < self.MCS_VERSION and version != 38:
                raise RuntimeError(f"Protocol version {version} unsupported")
        else:
            (tag,) = struct.unpack("B", await self.__aioread(1))
        logger.debug(f"Tag {tag} ({self.PACKET_BY_TAG[tag]})")
        size = await self.__aioread_varint32()
        logger.debug(f"Size {size}")
        if size >= 0:
            buf = await self.__aioread(size)
            logger.debug(f"HEX buffer:\n`{hexlify(buf)}`")
            Packet = self.PACKET_BY_TAG[tag]
            payload = Packet()
            payload.ParseFromString(buf)
            logger.debug(f"Payload:\n`{payload}`")
            return payload
        return None

    async def __aiolisthen_once(
        self,
        obj,
    ):
        load_der_private_key = serialization.load_der_private_key

        p = await self.__aiorecv()
        if type(p) is not DataMessageStanza:
            return
        if self._is_deleted_message(p):
            return
        crypto_key = self._app_data_by_key(p, "crypto-key")[3:]  # strip dh=
        salt = self._app_data_by_key(p, "encryption")[5:]  # strip salt=
        crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
        salt = urlsafe_b64decode(salt.encode("ascii"))
        der_data = self.credentials["keys"]["private"]
        der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
        secret = self.credentials["keys"]["secret"]
        secret = urlsafe_b64decode(secret.encode("ascii") + b"========")
        privkey = load_der_private_key(
            der_data, password=None, backend=default_backend()
        )
        decrypted = http_ece.decrypt(
            p.raw_data,
            salt=salt,
            private_key=privkey,
            dh=crypto_key,
            version="aesgcm",
            auth_secret=secret,
        )
        if inspect.iscoroutinefunction(self.callback):
            await self.callback(obj, json.loads(decrypted.decode("utf-8")), p)
        else:
            self.callback(obj, json.loads(decrypted.decode("utf-8")), p)

    async def __aiolisten_start(self):
        self.gcm_check_in(**self.credentials["gcm"])
        req = LoginRequest()
        req.adaptive_heartbeat = False
        req.auth_service = 2
        req.auth_token = self.credentials["gcm"]["securityToken"]
        req.id = "chrome-91.0.3234.0"
        req.domain = "mcs.android.com"
        req.device_id = "android-%x" % int(self.credentials["gcm"]["androidId"])
        req.network_type = 1
        req.resource = self.credentials["gcm"]["androidId"]
        req.user = self.credentials["gcm"]["androidId"]
        req.use_rmq2 = True
        req.setting.add(name="new_vc", value="1")
        req.received_persistent_id.extend(self.persistent_ids)
        await self.__aiosend(req)
        login_response = await self.__aiorecv(first=True)

    async def __aiolisten_coroutine(self):
        import cryptography.hazmat.primitives.serialization as serialization

        load_der_private_key = serialization.load_der_private_key

        while True:
            yield await self.__aiolisthen_once(load_der_private_key)

    async def listen_forever(self, timer: Union[int, float] = 1):
        """
        listens for push notifications

        credentials: credentials object returned by register()
        callback(obj, notification, data_message): called on notifications
        received_persistent_ids: any persistent id's you already received.
                                 array of strings
        obj: optional arbitrary value passed to callback
        """
        if not (self.__reader or self.__writer):
            await self.__open_connection()

        await self.__aiolisten_start()
        coroutine = self.__aiolisten_coroutine()
        try:
            while True:
                await coroutine.asend(None)
                await asyncio.sleep(timer)
        except Exception as e:
            self.__writer.close()
            await self.__writer.wait_closed()
