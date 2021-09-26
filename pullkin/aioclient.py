import asyncio
import inspect
import json
import struct
from asyncio import StreamWriter, StreamReader
from base64 import urlsafe_b64decode
from binascii import hexlify

from pullkin.client_base import PullkinBase
from .mcs_pb2 import *


class AioPullkin(PullkinBase):
    def __init__(self):
        ...

    async def __aioread(self, reader: StreamReader, size):
        buf = b""
        while len(buf) < size:
            buf += await reader.read(size - len(buf))
        return buf

    async def __aioread_varint32(self, reader: StreamReader):
        res = 0
        shift = 0
        while True:
            (b,) = struct.unpack("B", await self.__aioread(reader, 1))
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    def __send(self, s, packet):
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        self.__log.debug(packet)
        payload = packet.SerializeToString()
        buf = bytes(header) + self.__encode_varint32(len(payload)) + payload
        self.__log.debug(hexlify(buf))
        n = len(buf)
        total = 0
        while total < n:
            sent = s.send(buf[total:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            total += sent

    async def __aiosend(self, writer: StreamWriter, packet):
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        self.__log.debug(packet)
        payload = packet.SerializeToString()
        buf = bytes(header) + self.__encode_varint32(len(payload)) + payload
        self.__log.debug(hexlify(buf))
        n = len(buf)
        writer.write(buf)
        await writer.drain()

    async def __aiorecv(self, reader: StreamReader, first=False):
        if first:
            version, tag = struct.unpack("BB", await self.__aioread(reader, 2))
            self.__log.debug("version {}".format(version))
            if version < self.MCS_VERSION and version != 38:
                raise RuntimeError("protocol version {} unsupported".format(version))
        else:
            (tag,) = struct.unpack("B", await self.__aioread(reader, 1))
        self.__log.debug("tag {} ({})".format(tag, self.PACKET_BY_TAG[tag]))
        size = await self.__aioread_varint32(reader)
        self.__log.debug("size {}".format(size))
        if size >= 0:
            buf = await self.__aioread(reader, size)
            self.__log.debug(hexlify(buf))
            Packet = self.PACKET_BY_TAG[tag]
            payload = Packet()
            payload.ParseFromString(buf)
            self.__log.debug(payload)
            return payload
        return None

    async def __aiolisten(
        self,
        reader,
        writer,
        credentials,
        callback,
        persistent_ids,
        obj,
        timer=0,
        is_alive=True,
    ):
        import http_ece
        import cryptography.hazmat.primitives.serialization as serialization
        from cryptography.hazmat.backends import default_backend

        load_der_private_key = serialization.load_der_private_key

        self.gcm_check_in(**credentials["gcm"])
        req = LoginRequest()
        req.adaptive_heartbeat = False
        req.auth_service = 2
        req.auth_token = credentials["gcm"]["securityToken"]
        req.id = "chrome-91.0.3234.0"
        req.domain = "mcs.android.com"
        req.device_id = "android-%x" % int(credentials["gcm"]["androidId"])
        req.network_type = 1
        req.resource = credentials["gcm"]["androidId"]
        req.user = credentials["gcm"]["androidId"]
        req.use_rmq2 = True
        req.setting.add(name="new_vc", value="1")
        req.received_persistent_id.extend(persistent_ids)
        await self.__aiosend(writer, req)
        login_response = await self.__aiorecv(reader, first=True)
        while is_alive:
            p = await self.__aiorecv(reader)
            if type(p) is not DataMessageStanza:
                continue
            crypto_key = self.__app_data_by_key(p, "crypto-key")[3:]  # strip dh=
            salt = self.__app_data_by_key(p, "encryption")[5:]  # strip salt=
            crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
            salt = urlsafe_b64decode(salt.encode("ascii"))
            der_data = credentials["keys"]["private"]
            der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
            secret = credentials["keys"]["secret"]
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
            if inspect.iscoroutinefunction(callback):
                await callback(obj, json.loads(decrypted.decode("utf-8")), p)
            else:
                callback(obj, json.loads(decrypted.decode("utf-8")), p)
            if timer:
                await asyncio.sleep(timer)

    async def aiolisten(
        self,
        credentials,
        callback,
        received_persistent_ids=None,
        obj=None,
        timer=0,
        is_alive=True,
    ):
        """
        listens for push notifications

        credentials: credentials object returned by register()
        callback(obj, notification, data_message): called on notifications
        received_persistent_ids: any persistent id's you already received.
                                 array of strings
        obj: optional arbitrary value passed to callback
        """
        if received_persistent_ids is None:
            received_persistent_ids = []
        import ssl

        host = "mtalk.google.com"
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(host, 5228, ssl=ssl_ctx)
        self.__log.debug("connected to ssl socket")
        await self.__aiolisten(
            reader,
            writer,
            credentials,
            callback,
            received_persistent_ids,
            obj,
            timer,
            is_alive,
        )
        writer.close()
        await writer.wait_closed()
