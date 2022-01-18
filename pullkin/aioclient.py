import asyncio
import inspect
import json
import struct
import traceback
from asyncio import StreamReader, StreamWriter
from base64 import urlsafe_b64decode
from binascii import hexlify
from typing import Callable, Optional, Union, AsyncGenerator

import cryptography.hazmat.primitives.serialization as serialization
import http_ece
from cryptography.hazmat.backends import default_backend
from loguru import logger

from pullkin.client_base import PullkinBase
from pullkin.proto.mcs_proto import *
from pullkin.models.message import Message

logger.disable("pullkin")


class AioPullkin(PullkinBase):
    def __init__(self):
        super().__init__()
        self.__reader: Optional[StreamReader] = None
        self.__writer: Optional[StreamWriter] = None
        self.credentials: dict = {}
        self.persistent_ids: list = []
        self.callback: Callable = None
        self.on_notification_handlers: list = []
        self.once = True

    def on_notification(self, filter: Callable = lambda *a, **k: True):
        """
        Decorator

        Registers a new callback with filter rule to trigger this callback

        First param to be passed into filter or callback: some object. Now is empty dict.
        Later you will be able to passed your object
        Second param: Notification object. You can read about Notification here: TODO: add a link
        Third param: Message object that get from socket. With all data about message. Read hereL TODO: add a link

        :: python code
            from pullkin import AioPullkin, Notification, DataMessageStanza as Message
            pullkin = AuiPullkin()

            @pullkin.on_notification(lambda o, n, m: n.title == "Moi koleni zamerzli")
            def on_zemfira(obj, notification, message):
                print(notification.notification.body)

            @pullkin.on_notification(lambda o, n, m: n.priority == "normal")
            async def on_normal(obj: dict, notification: Notification, message: Message):
                print(f"#{message.id} @{message.sent})
                print(notification")
                await asyncio.sleep(2)
                print("=-)")

        """

        def decorator(callback):
            self.on_notification_handlers.append(
                {"callback": callback, "filter": filter}
            )
            return callback

        return decorator

    def register_on_notification_handler(
        self, filter: Callable = None, callback: Callable = None
    ):
        """
        Function

        Registers a new callback with filter rule to trigger this callback

        filter: rule for calling thit callback
        callback: function to be called if the filter-function returns True

        First param to be passed into filter and callback: some object. Now is empty dict.
        Later you will be able to passed your object
        Second param: Notification object. You can read about Notification here: TODO: add a link
        Third param: Message object that get from socket. With all data about message. Read hereL TODO: add a link

        :: python code
            from pullkin import AioPullkin, Notification, DataMessageStanza as Message
            pullkin = AuiPullkin()

            @pullkin.on_notification(lambda o, n, m: n.title == "Moi koleni zamerzli")
            def on_zemfira(obj, notification, message):
                print(notification.notification.body)

            @pullkin.on_notification(lambda o, n, m: n.priority == "normal")
            async def on_normal(obj: dict, notification: Notification, message: Message):
                print(f"#{message.id} @{message.sent})
                print(notification")
                await asyncio.sleep(2)
                print("=-)")

        """
        self.on_notification_handlers.append({"callback": callback, "filter": filter})

    async def __run_on_notification_callbacks(self, obj, notification, data_message):
        x = 0
        for handler in self.on_notification_handlers:
            if handler["filter"](obj, notification, data_message):
                if inspect.iscoroutinefunction(handler["callback"]):
                    await handler["callback"](obj, notification, data_message)
                else:
                    handler["callback"](obj, notification, data_message)
                x += 1
                if self.once:
                    break
        else:
            if self.callback:
                if inspect.iscoroutinefunction(self.callback):
                    await self.callback(obj, notification, data_message)
                else:
                    self.callback(obj, notification, data_message)

        if not x:
            logger.debug('No one callback was called')

    @classmethod
    async def aioregister(cls, sender_id):
        """
        Async version. Register "app" for receive pushed

        Returns "app"-credential in dict for receive "personal" push by token
        """
        return await cls._register(sender_id)

    async def __open_connection(self) -> None:
        import ssl

        ssl_ctx = ssl.create_default_context()
        self.__reader, self.__writer = await asyncio.open_connection(
            self.PUSH_HOST, self.PUSH_PORT, ssl=ssl_ctx
        )
        logger.debug(
            f"Connected to SSL socket {self.PUSH_HOST}:{self.PUSH_PORT} with default ssl_context"
        )

    async def __aioread(self, size) -> bytes:
        buf = b""
        while len(buf) < size:
            buf += await self.__reader.read(size - len(buf))
        return buf

    async def __aioread_varint32(self) -> int:
        res = 0
        shift = 0
        while True:
            (b,) = struct.unpack("B", await self.__aioread(1))
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    async def __aiosend(self, packet) -> None:
        logger.debug(f"Send")
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        logger.debug(f"Packet:\n'{packet}'")
        payload = packet.SerializeToString()
        buf = bytes(header) + self._encode_varint32(len(payload)) + payload
        logger.debug(f"HEX buffer:\n`{hexlify(buf)}`")
        self.__writer.write(buf)
        await self.__writer.drain()

    async def __aiorecv(self, first=False) -> Optional[PullkinBase.packet_union]:
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
            packet_class = self.PACKET_BY_TAG[tag]
            payload = packet_class()
            payload.parse(buf)
            logger.debug(f"Payload:\n`{payload}`")
            return payload
        return None

    async def __aiolisten_once(
        self,
    ) -> None:
        load_der_private_key = serialization.load_der_private_key

        p = await self.__aiorecv()
        if type(p) is not DataMessageStanza:
            return
        if self._is_deleted_message(p):
            return
        crypto_key = self._app_data_by_key(p, "crypto-key", False)
        salt = self._app_data_by_key(p, "encryption", False)
        logger.debug(f"crypto-key: {crypto_key}, salt: {salt}")
        if not (salt and crypto_key):
            return
        crypto_key = crypto_key[3:]  # strip dh=
        salt = salt[5:]  # strip salt=
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
        notification = Message(json.loads(decrypted.decode("utf-8")))
        await self.__run_on_notification_callbacks({}, notification, p)

    async def __aiolisten_start(self) -> None:
        await self.gcm_check_in(**self.credentials["gcm"])
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
        req.setting.append(Setting(name="new_vc", value="1"))
        req.received_persistent_id.extend(self.persistent_ids)
        await self.__aiosend(req)
        await self.__aiorecv(first=True)

    async def __aiolisten_coroutine(self) -> AsyncGenerator:
        while True:
            yield await self.__aiolisthen_once()

    async def listen_coroutine(self) -> AsyncGenerator:
        """
        Return a listener-coroutine

        Every coroutine iteration is one received push
        (or not, because it starts reading and waiting for data on socket)

        You can use coroutine like this, for example:

        :: python code
            # <some code>

            await coroutine.asend(None)  # One push will be received and distributed

            # <some code>

            for _ in range(10): # Ten pushes will be received
                await coroutine.asend(None)

            # <some code>

        :return: coroutine
        """
        if not (self.__reader or self.__writer):
            await self.__open_connection()
        await self.__aiolisten_start()
        coroutine = self.__aiolisten_coroutine()
        return coroutine

    async def listen_forever(self, timer: Union[int, float] = 0.05) -> None:
        """
        Listens for push notifications

        Runs an endless loop for reading notifications and distributing among callbacks based on filter results

        :param timer: timer in seconds between receive iteration
        :type timer: ``int`` or ``float``, optional, default ``0.05``
        """
        if not (self.__reader or self.__writer):
            await self.__open_connection()

        await self.__aiolisten_start()
        coroutine = self.__aiolisten_coroutine()
        try:
            while self.__reader and self.__writer:
                await coroutine.asend(None)
                await asyncio.sleep(timer)
        except Exception as e:
            print(traceback.format_exc())
        finally:
            if self.__writer:
                self.__writer.close()
                await self.__writer.wait_closed()

    async def close(self):
        try:
            if self._http_client:
                await self._http_client.aclose()
            if self.__writer:
                self.__writer.close()
                await self.__writer.wait_closed()
            self.__writer = None
            self.__reader = None
        except ConnectionResetError:
            return
