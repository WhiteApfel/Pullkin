import asyncio
import inspect
import json
import ssl
import struct
import uuid
from base64 import urlsafe_b64decode
from binascii import hexlify
from functools import wraps
from typing import Any, AsyncGenerator, Awaitable, Callable, Optional, TypeVar

import cryptography.hazmat.primitives.serialization as serialization
import http_ece
from cryptography.hazmat.backends import default_backend
from loguru import logger

from pullkin.core import PullkinAppData, PullkinCore
from pullkin.models import AppCredentials
from pullkin.models.message import Message, NotificationData
from pullkin.proto.mcs_proto import DataMessageStanza, LoginRequest, Setting

logger.disable("pullkin")

T = TypeVar("T", bound=Callable[[Message | None, DataMessageStanza], Awaitable | None])


class Pullkin(PullkinCore):
    def __init__(self):
        super().__init__()
        self.apps: dict[str, PullkinAppData] = {}

        self.on_notification_handlers: list = []
        self.once: bool = True
        self._started: bool = False

    def on_notification(
        self,
        handler_filter: Callable[
            [Message, DataMessageStanza], None
        ] = lambda *a, **k: True,
    ) -> Callable[[T], T]:
        """
        Registers a new callback with a filter rule to trigger this callback.

        Args:
            handler_filter: A callable object that filters notifications.
                It takes two parameters: the message and the data message stanza.
                If the callable returns True, the callback will be triggered.

        Returns:
            A decorator that registers the callback.

        Example:
            ```python
            from pullkin import Pullkin, Message, DataMessageStanza
            pullkin = AuiPullkin()

            @pullkin.on_notification(lambda m, d: m.notification.title == "Moi koleni zamerzli")
            def on_zemfira(message: Message, data_message: DataMessageStanza):
                print(message.notification.body)

            @pullkin.on_notification(lambda m, d: m.priority == "normal")
            async def on_normal(message: Message, data_message: DataMessageStanza):
                print(f"#{data_message.id} @{data_message.sent}")
                print(message.notification)
                await asyncio.sleep(2)
                print("=-)")
            ```
        """

        @wraps
        def decorator(
            callback: T,
        ) -> T:
            self.on_notification_handlers.append(
                {"callback": callback, "filter": handler_filter}
            )
            return callback

        return decorator

    @staticmethod
    async def _process_handler(
        handler, message: Message, data_message: DataMessageStanza
    ) -> None:
        for field, annotation in handler["callback"].__annotations__.items():
            if (
                field != "return"
                and issubclass(annotation, Message)
                and message is not None
            ):
                message = message.to_another_model(annotation)
        if inspect.iscoroutinefunction(handler["callback"]):
            await handler["callback"](message, data_message)
        else:
            handler["callback"](message, data_message)

    async def _run_on_notification_callbacks(
        self, message: Message, data_message: DataMessageStanza
    ) -> None:
        x = 0
        for handler in self.on_notification_handlers:
            if handler["filter"](message, data_message):
                await self._process_handler(handler, message, data_message)
                x += 1
                if self.once:
                    break
        if not x:
            logger.debug("No one callback was called")

    async def __open_connection(self, sender_id: str) -> None:
        import ssl

        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(
            self.PUSH_HOST, self.PUSH_PORT, ssl=ssl_ctx
        )
        self.apps[sender_id].reader = reader
        self.apps[sender_id].writer = writer

        logger.debug(
            f"Connected to SSL socket {self.PUSH_HOST}:{self.PUSH_PORT} with default"
            " ssl_context"
        )

    async def __read(self, sender_id: str, size: int) -> bytes:
        buf = b""
        while len(buf) < size:
            buf += await self.apps[sender_id].reader.read(size - len(buf))
        return buf

    async def __read_varint32(self, sender_id: str) -> int:
        res = 0
        shift = 0
        while True:
            (b,) = struct.unpack("B", await self.__read(sender_id, 1))
            res |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return res

    async def __send(self, sender_id: str, packet) -> None:
        logger.debug(f"Send #{(send_id := str(uuid.uuid4()))}")
        header = bytearray([self.MCS_VERSION, self.PACKET_BY_TAG.index(type(packet))])
        logger.debug(f"Packet:\n'{packet}' #{send_id}")
        payload = packet.SerializeToString()
        buf = bytes(header) + self._encode_varint32(len(payload)) + payload
        logger.debug(f"HEX buffer:\n`{hexlify(buf)}` #{send_id}")
        self.apps[sender_id].writer.write(buf)
        await self.apps[sender_id].writer.drain()

    async def __recv(
        self, sender_id: str, first=False
    ) -> Optional[PullkinCore.packet_union]:
        logger.debug(f"Receive #{(recv_id := str(uuid.uuid4()))}")
        if first:
            version, tag = struct.unpack("BB", await self.__read(sender_id, 2))
            logger.debug(f"Version {version}")
            if version < self.MCS_VERSION and version != 38:
                logger.error(f"Protocol version {version} unsupported")
                raise RuntimeError(f"Protocol version {version} unsupported")
        else:
            (tag,) = struct.unpack("B", await self.__read(sender_id, 1))
        logger.debug(f"Tag {tag} ({self.PACKET_BY_TAG[tag]}) #{recv_id}")
        size = await self.__read_varint32(sender_id)
        logger.debug(f"Size {size} #{recv_id}")
        if size >= 0:
            buf = await self.__read(sender_id, size)
            logger.debug(f"HEX buffer:\n`{hexlify(buf)}` #{recv_id}")
            packet_class = self.PACKET_BY_TAG[tag]
            payload = packet_class()
            payload.parse(buf)
            logger.debug(f"Payload:\n`{payload}` #{recv_id}")
            return payload
        return None

    async def __listen_once(self, sender_id: str) -> Message | None:
        load_der_private_key = serialization.load_der_private_key

        p = await self.__recv(sender_id)
        if not isinstance(p, DataMessageStanza):
            logger.warning(f"Wow: other message {type(p)=}: {p.to_dict()}")
            return
        if self._is_deleted_message(p):
            return  # TODO: add on deleted message
        p: DataMessageStanza
        crypto_key = self._app_data_by_key(p, "crypto-key", False)
        salt = self._app_data_by_key(p, "encryption", False)
        logger.debug(f"crypto-key: {crypto_key}, salt: {salt}")
        if not (salt and crypto_key):
            message = None
        else:
            credentials = self.apps.get(p.from_).credentials
            crypto_key = crypto_key[3:]  # strip dh=
            salt = salt[5:]  # strip salt=
            crypto_key = urlsafe_b64decode(crypto_key.encode("ascii"))
            salt = urlsafe_b64decode(salt.encode("ascii"))
            der_data = credentials.keys.private
            der_data = urlsafe_b64decode(der_data.encode("ascii") + b"========")
            secret = credentials.keys.secret
            secret = urlsafe_b64decode(secret.encode("ascii") + b"========")
            privkey = load_der_private_key(
                der_data, password=None, backend=default_backend()
            )
            decrypted = http_ece.decrypt(
                p.raw_data,  # noqa
                salt=salt,  # noqa
                private_key=privkey,  # noqa
                dh=crypto_key,  # noqa
                version="aesgcm",
                auth_secret=secret,  # noqa
            )
            data: dict[str, Any] = json.loads(decrypted.decode("utf-8"))
            message = Message[NotificationData].model_validate(data)
        await self._run_on_notification_callbacks(message, p)
        return message

    async def _listen_start(
        self,
        sender_id: int | str | None = None,
        credentials: AppCredentials | None = None,
        persistent_ids: set[str] | None = None,
    ) -> None:
        """
        Connect "device" to "app" cloud messages.
        After this method, messages will be delivered to this app.

        Args:
            sender_id:
            credentials:
            persistent_ids:

        Returns:

        """
        if not (self.apps[sender_id].reader or self.apps[sender_id].writer):
            await self.__open_connection(sender_id)

        await self.gcm_check_in(credentials.gcm)
        req = LoginRequest()
        req.adaptive_heartbeat = False
        req.auth_service = 2
        req.auth_token = credentials.gcm.security_token
        req.id = "fcm-23.1.1"
        req.domain = "mcs.android.com"
        req.device_id = f"android-{credentials.gcm.android_id}"
        req.network_type = 1
        req.resource = credentials.gcm.android_id
        req.user = credentials.gcm.android_id
        req.use_rmq2 = True
        req.setting.append(Setting(name="new_vc", value="1"))
        req.received_persistent_id.extend(persistent_ids)
        try:
            await self.__send(sender_id, packet=req)
            await self.__recv(sender_id, first=True)
        except:  # noqa
            logger.exception("Error during send login request")
            raise
        self.apps[sender_id].is_started = True

    async def __listen_coroutine(
        self, sender_id: str
    ) -> AsyncGenerator[Message | None, None]:
        while True:
            yield await self.__listen_once(sender_id)
            if not self.apps[sender_id].is_started:
                return

    async def listen_coroutine(
        self,
        sender_id: int | str | None = None,
    ) -> AsyncGenerator[Message | None, None]:
        """
        Creates a coroutine to listen for push notifications.

        This coroutine yields a received push notification on each iteration. If no notification
        is available, it waits for data on the socket.

        Args:
            sender_id (int | str | None): The sender ID to filter notifications for.
                If None, listen to all notifications.

        Returns:
            An asynchronous generator that yields each
                received push notification, or None if no notification is received.

        Yields:
            Message | None: A received push notification message, or None if no notification is received.

        Example:
            ```python
            # Perform some initial setup...

            # Receive and distribute one push notification.
            await coroutine.asend(None)

            # Perform some other tasks...

            # Receive and distribute ten push notifications.
            for _ in range(10):
                await coroutine.asend(None)

            # Perform some final tasks...
            ```
        """
        # TODO: add docs
        coroutine = self.__listen_coroutine(sender_id)
        return coroutine

    async def _wait_start(self, sender_id: str):
        while not all(
            self.apps[sender_id].__getattribute__(i)
            for i in ["is_started", "reader", "writer"]
        ):
            await asyncio.sleep(0.01)

    async def _run_listener(
        self,
        sender_id: str,
        timer: int | float = 0.05,
    ) -> None:
        if not (self.apps[sender_id].reader or self.apps[sender_id].writer):
            await self.__open_connection(sender_id)

        coroutine = self.__listen_coroutine(sender_id)

        try:
            while self.apps[sender_id].reader and self.apps[sender_id].writer:
                await coroutine.asend(None)
                await asyncio.sleep(timer)
        except (KeyboardInterrupt, asyncio.CancelledError):
            await self.stop()
        except:  # noqa: E722
            logger.exception("Error while listen:")
            await self.stop()
            raise

    async def add_app(
        self,
        sender_id: str,
        credentials: AppCredentials,
        persistent_ids: set[str] | None = None,
    ) -> None:
        """
        Subscribe a device to a specific app.

        This method is used to subscribe a device to a specific app,
        allowing it to receive notifications from that app.

        Args:
            sender_id (str): The sender ID of the app.
            credentials (AppCredentials): The credentials for the app.
            persistent_ids (set[str]): The persistent IDs for the app.

        Returns:
            None
        """
        sender_id = self._normalize_sender_id(sender_id)
        credentials = self._get_or_validate_credentials(sender_id, credentials)
        persistent_ids = self._normalize_persistent_ids(persistent_ids)

        self._setup_app_data(sender_id, credentials, persistent_ids)

        task = asyncio.create_task(
            self._listen_start(sender_id, credentials, persistent_ids)
        )
        try:
            await self._wait_for_app_to_start(sender_id, task)
        except asyncio.exceptions.TimeoutError:
            logger.error("Timeout subscribe device to app 10s")
        except (KeyboardInterrupt, asyncio.CancelledError):
            return
        except:  # noqa: E722
            logger.exception("Wait start error:")
            raise

    @staticmethod
    def _normalize_sender_id(sender_id: str | int) -> str:
        return str(sender_id)

    @staticmethod
    def _normalize_persistent_ids(persistent_ids: set[str] | None) -> set[str]:
        return persistent_ids or set()

    def _get_or_validate_credentials(
        self, sender_id: str, credentials: AppCredentials | None
    ) -> AppCredentials:
        if credentials is None:
            if sender_id in self.apps:
                return self.apps[sender_id].credentials
            elif len(self.apps) == 1:
                return self.apps.get(list(self.apps.keys())[0]).credentials
        return credentials

    def _setup_app_data(
        self, sender_id: str, credentials: AppCredentials, persistent_ids: set[str]
    ) -> None:
        if sender_id not in self.apps:
            self.apps[sender_id] = PullkinAppData(
                credentials=credentials,
                persistent_ids=persistent_ids,
                is_started=False,
                reader=None,
                writer=None,
                listener=None,
            )
        else:
            self.apps[sender_id].credentials = credentials
            self.apps[sender_id].persistent_ids = persistent_ids

        if credentials is None:
            raise ValueError("Credentials is None. See docs")  # TODO: add link

    async def _wait_for_app_to_start(self, sender_id: str, task: asyncio.Task) -> None:
        try:
            await asyncio.wait_for(self._wait_start(sender_id), timeout=10)
        except asyncio.exceptions.TimeoutError:
            task.cancel()

    async def run(
        self,
        sender_ids: list[str] | None = None,
        timer: int | float = 0.05,
    ) -> None:
        """
        Listens for push notifications in the background.

        This method runs an endless loop that reads incoming notifications and
        distributes them among registered callbacks based on filter results.

        Args:
            sender_ids: A list of sender IDs to listen for notifications from.
                If `None`, all registered via `add_app()` sender IDs will be listened to.
            timer: The time interval in seconds between each receive-iteration.
                Defaults to 0.05 seconds.

        Returns:
            None
        """
        # TODO: add docs

        for sender_id in self.apps:
            if sender_ids is None or sender_id in sender_ids:
                self.apps[sender_id].listener = asyncio.create_task(
                    self._run_listener(sender_id, timer)
                )

    async def _close_app(self, sender_id: str):
        app_data = self.apps[sender_id]

        if app_data.writer:
            try:
                app_data.is_started = False
                app_data.writer.close()
                try:
                    await asyncio.wait_for(app_data.writer.wait_closed(), 5)
                except asyncio.exceptions.TimeoutError:  # noqa
                    ...  # noqa
                app_data.writer = None
                app_data.reader = None
            except (
                ConnectionResetError,
                ssl.SSLError,
            ):
                pass
            except:  # noqa: E722
                logger.exception("Error during close Pullkin:")
                raise

        if app_data.listener:
            app_data.listener.cancel()

        del self.apps[sender_id]

    async def stop(self, sender_id: str | None = None) -> None:
        """
        Closes the connection for the specified sender ID or all sender IDs if `None` is provided.

        Args:
            sender_id (str | None): The sender ID to close the connection for. `None` for all.

        Returns:
            None

        """
        if sender_id is None:
            for sender_id in set(self.apps.keys()):
                await self._close_app(sender_id)
        else:
            await self._close_app(sender_id)

        if len(self.apps) == 0:
            await self._http_client.aclose()
            self._http_client = None
