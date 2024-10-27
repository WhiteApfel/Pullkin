import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from asyncio import StreamReader, StreamWriter, Task
from base64 import b64encode, urlsafe_b64encode
from dataclasses import dataclass, field
from typing import Optional, Union
from urllib.parse import urlencode

from httpx import AsyncClient, Request
from loguru import logger
from oscrypto.asymmetric import generate_pair
from pydantic import ValidationError

from pullkin.exceptions import PullkinRegistrationRetriesError, PullkinResponseError
from pullkin.models import AppCredentials, AppCredentialsGcm
from pullkin.models.credentials import (
    AppCredentialsFcm,
    AppCredentialsKeys,
    FirebaseInstallation,
)
from pullkin.proto.android_checkin_proto import AndroidCheckinProto, ChromeBuildProto
from pullkin.proto.checkin_proto import AndroidCheckinRequest, AndroidCheckinResponse
from pullkin.proto.mcs_proto import (
    Close,
    DataMessageStanza,
    HeartbeatAck,
    HeartbeatPing,
    IqStanza,
    LoginRequest,
    LoginResponse,
    StreamErrorStanza,
)

logger.disable("pullkin")


@dataclass
class PullkinAppData:
    credentials: AppCredentials | None = None
    persistent_ids: set[str] = field(default_factory=set)
    is_started: bool = False
    reader: StreamReader | None = None
    writer: StreamWriter | None = None
    listener: Task | None = None


class PullkinCore:
    """
    Core methods for GCM and FCM registration.

    This class contains all the underlying methods for GCM and FCM registration.
    However, users should usually only care about the Pullkin.register() method.
    """

    unicode = str

    SERVER_KEY = (
        b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
        b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
        b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
        b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
    )

    REGISTER_URL = "https://android.apis.google.com/c2dm/register3"
    CHECKIN_URL = "https://android.clients.google.com/checkin"
    FCM_SUBSCRIBE = "https://fcm.googleapis.com/fcm/connect/subscribe"
    FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send"
    FCM_INSTALLATION_ENDPOINT_PATTERN = (
        "https://firebaseinstallations.googleapis.com/v1/projects/{}/installations"
    )
    FCM_REGISTER_ENDPOINT_PATTERN = (
        "https://fcmregistrations.googleapis.com/v1/projects/{}/registrations"
    )

    PUSH_HOST = "mtalk.google.com"
    PUSH_PORT = 5228

    MCS_VERSION = 41

    PACKET_BY_TAG = [
        HeartbeatPing,
        HeartbeatAck,
        LoginRequest,
        LoginResponse,
        Close,
        "MessageStanza",
        "PresenceStanza",
        IqStanza,
        DataMessageStanza,
        "BatchPresenceStanza",
        StreamErrorStanza,
        "HttpRequest",
        "HttpResponse",
        "BindAccountRequest",
        "BindAccountResponse",
        "TalkMetadata",
    ]
    packet_union = Union[
        HeartbeatPing,
        HeartbeatAck,
        LoginRequest,
        LoginResponse,
        Close,
        IqStanza,
        DataMessageStanza,
        StreamErrorStanza,
    ]

    def __init__(self):
        self._http_client = None

    @property
    def http_client(self):
        if not self._http_client:
            self._http_client = AsyncClient()
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    @classmethod
    def _urlsafe_base64(cls, data):
        """
        base64-encodes data with -_ instead of +/ and removes all = padding.
        also strips newlines

        returns a string
        """
        res = urlsafe_b64encode(data).replace(b"=", b"")
        return res.replace(b"\n", b"").decode("ascii")

    @classmethod
    def generate_fid(cls) -> str:
        fid_byte_array = bytearray(17)
        fid_byte_array[:] = secrets.token_bytes(17)

        # Replace the first 4 random bits with the constant FID header of 0b0111.
        fid_byte_array[0] = 0b01110000 + (fid_byte_array[0] % 0b00010000)

        b64 = base64.b64encode(fid_byte_array).decode("utf-8")
        b64_safe = b64.replace("+", "-").replace("/", "_")
        fid = b64_safe[:22]

        if "+" in fid or "/" in fid:
            fid = cls.generate_fid()
        return fid

    async def _do_request(self, req, retries=5, decode=False) -> bytes | str:
        for _ in range(retries):
            try:
                resp = await self.http_client.send(req, follow_redirects=True)
                resp_data = resp.content
                logger.debug(f"Response:\n{resp_data}")
                return resp_data.decode("utf-8") if decode else resp_data
            except ValueError:
                logger.exception("ValueError during send request")
            except (KeyboardInterrupt, asyncio.CancelledError):
                raise
            except:  # noqa
                logger.exception("Error during request:")
                time.sleep(1)
        raise ValueError(f"Failed to get a response with {retries} retries")

    async def fcm_installation(
        self,
        app_id: str,
        api_key: str,
        android_cert: str,
        app_package: str,
        firebase_project_id: str,
    ) -> FirebaseInstallation:
        """
        Performs FCM installation.

        Args:
            app_id (str): App ID of the Firebase app.
            api_key (str): API key of the Firebase app.
            android_cert (str): Android certificate of the Firebase app.
            app_package (str): Package name of the app.
            firebase_project_id (str): Firebase project ID of the app.

        Returns:
            The device installation data of the firebase app.
        """
        data = {
            "fid": self.generate_fid(),
            "authVersion": "FIS_v2",
            "appId": app_id,
            "sdkVersion": "a:18.0.0",
        }
        headers = {
            "x-goog-api-key": api_key,
            "x-android-cert": android_cert,
            "x-android-package": app_package,
        }

        req = self.http_client.build_request(
            method="POST",
            url=self.FCM_INSTALLATION_ENDPOINT_PATTERN.format(firebase_project_id),
            headers=headers,
            json=data,
            timeout=8,
        )
        resp = await self._do_request(req)

        resp_data = json.loads(resp.decode("utf-8"))

        return FirebaseInstallation(
            name=resp_data["name"],
            fid=resp_data["fid"],
            refresh_token=resp_data["refreshToken"],
            auth_token=resp_data["authToken"]["token"],
            auth_token_expires_in=int(resp_data["authToken"]["expiresIn"][:-1]),
        )

    async def fcm_register(
        self,
        gcm_token: str,
        api_key: str,
        firebase_project_id: str,
        firebase_installation: FirebaseInstallation,
        retries: int = 5,
    ) -> tuple[AppCredentialsKeys, AppCredentialsFcm]:
        """
        Generates a key pair and registers a GCM token.

        This method may return an error in the `AppCredentialsFcm.error` field.
        To validate the success of the registration, check the `AppCredentialsFcm.is_success` field.
        For more details about the error, if any, check the `AppCredentialsFcm.error` field.

        Args:
            gcm_token (str): The subscription GCM token returned by `Pullkin.gcm_register(...)`.
            api_key (str): The API key for the Firebase project.
            firebase_project_id (str): The ID of the Firebase project.
            firebase_installation (FirebaseInstallation): The Firebase installation data.
            retries (int, optional): The number of retries for the registration.

        Returns:
            A tuple containing the generated key pair and the FCM registration data.
        """
        # Francesco152 used this analyzer to figure out how to slice the asn1 structs
        # https://lapo.it/asn1js
        # first byte of public key is skipped for some reason
        # maybe it's always zero
        public, private = generate_pair("ec", curve=self.unicode("secp256r1"))

        logger.debug(f"# Public key {b64encode(public.asn1.dump())}")
        logger.debug(f"# Private key {b64encode(private.asn1.dump())}")

        keys = AppCredentialsKeys(
            public=self._urlsafe_base64(public.asn1.dump()[26:]),
            private=self._urlsafe_base64(private.asn1.dump()),
            secret=self._urlsafe_base64(os.urandom(16)),
        )

        body = {
            "web": {
                "applicationPubKey": "",
                "auth": keys.secret,
                "endpoint": f"{self.FCM_ENDPOINT}/{gcm_token}",
                "p256dh": keys.public,
            },
        }
        headers = {
            "x-goog-api-key": api_key,
            "x-goog-firebase-installations-auth": firebase_installation.auth_token,
        }
        logger.debug(f"Data: {body}")

        req = Request(
            method="POST",
            url=self.FCM_REGISTER_ENDPOINT_PATTERN.format(firebase_project_id),
            headers=headers,
            json=body,
        )
        resp_data = await self._do_request(req, retries, decode=True)

        try:
            fcm = AppCredentialsFcm.model_validate_json(resp_data)
        except ValidationError as e:
            logger.exception(e)
            raise PullkinResponseError(
                f"Failed to parse FCM response: {resp_data}"
            ) from e

        return keys, fcm

    async def gcm_check_in(
        self, credentials: Optional[AppCredentialsGcm] = None
    ) -> AndroidCheckinResponse:
        """
        Perform a check-in request to obtain the android_id and security token.

        The android_id and security_token are required for the GCM registration,
        and will be returned in the response.

        Args:
            credentials (Optional[AppCredentialsGcm]): The credentials to use for the GCM check-in.
                Required for first check-in.

        Returns:
            The response to the check-in request, containing the android_id, security_token and more.
        """
        chrome = ChromeBuildProto()
        chrome.platform = 3
        chrome.chrome_version = "111.0.5563.0"
        chrome.channel = 1

        checkin = AndroidCheckinProto()
        checkin.type = 3
        checkin.chrome_build.from_dict(chrome.to_dict())

        payload = AndroidCheckinRequest()
        payload.user_serial_number = 0
        payload.checkin.from_dict(checkin.to_dict())
        payload.version = 3
        if credentials:
            payload.id = int(credentials.android_id)
            payload.security_token = int(credentials.security_token)

        logger.debug(f"Payload: \n{payload}")
        req = self.http_client.build_request(
            method="POST",
            url=self.CHECKIN_URL,
            headers={"Content-Type": "application/x-protobuf"},
            content=payload.SerializeToString(),
            timeout=5,
        )
        resp_data = await self._do_request(req)
        resp = AndroidCheckinResponse()
        resp.parse(resp_data)
        logger.debug(f"Response: \n{resp}")
        return resp

    async def gcm_register(
        self,
        sender_id: str,
        app_id: str,
        api_key: str | None = None,
        firebase_project_id: str | None = None,
        android_cert: str | None = None,
        app_name: str = "org.chromium.linux",
        retries: int = 5,
        current_retry: int = 0,
        **_,
    ) -> AppCredentialsGcm:
        """
        Registers a device to GCM.

        This method performs the GCM device registration, which is a mandatory step
        before a device can receive push notifications.
        The method performs the following steps:

        1. Performs a Chrome build check-in to obtain the Android ID and
           security token.
        2. Registers the device to GCM using the obtained Android ID and
           security token.

        The registration to Firebase is optional and can be skipped if the
        required parameters are not provided.

        Args:
            sender_id (str): The Sender ID of the app.
            app_id (str): The app ID in the form of "1:123123:android".
            api_key (str): The API key in the form of "AIzaSy...".
            firebase_project_id (str): The project ID of the Firebase project.
            android_cert (str): The android cert hash as a base64 string.
            app_name (str): The package name of the app.
            retries (int): The number of failed requests before giving up.
            current_retry (int): The current retry counts. Default to 0.

        Returns:
            The GCM registration data.
        """
        # contains android_id, security_token and more
        checkin_result = await self.gcm_check_in()
        logger.debug(f"Check_in: \n{checkin_result}")

        installation_result: FirebaseInstallation | None = None
        if all((api_key, android_cert, app_name, firebase_project_id)):
            installation_result = await self.fcm_installation(
                app_id, api_key, android_cert, app_name, firebase_project_id
            )
        else:
            logger.warning("Not all credentials provided, skip FCM installation")

        body = {
            "X-subtype": sender_id,
            "sender": sender_id,
            "X-app_ver": "1111",
            "X-osv": "25",
            "X-cliv": "fcm-23.1.1",
            "X-gmsv": "231114044",
            "X-scope": "*",
            "X-gmp_app_id": app_id,
            "X-app_ver_name": "1.1.1.1",
            "app": app_name,
            "device": checkin_result.android_id,
            "app_ver": "1111",
            "gcm_ver": "231114044",
            "plat": "0",
            "cert": android_cert,
            "target_ver": "28",
        }

        if installation_result is not None:
            body |= {
                "X-Goog-Firebase-Installations-Auth": installation_result.auth_token,
                "X-appid": installation_result.fid,
                "X-firebase-app-name-hash": (
                    base64.b64encode(hashlib.sha1(app_name.encode()).digest())
                    .decode("utf-8")
                    .rstrip("=")
                ),
            }

        headers = {
            "app": app_name,
            "app_ver": "111",
            "gcm_ver": "231114044",
            "user-agent": "Android-GCM/1.5 (Pullkin WhiteApfel)",
            "authorization": (
                f"AidLogin {checkin_result.android_id}:{checkin_result.security_token}"
            ),
        }

        logger.debug(f"Data:\n{urlencode(body)}")

        req = Request(
            method="POST",
            url=self.REGISTER_URL,
            headers=headers,
            data=body,
        )

        resp_data = await self._do_request(req, retries, decode=True)

        if "Error" in resp_data:
            logger.error(f"Register request has failed with {resp_data}")
            raise PullkinResponseError(f"GCM registration error: {resp_data}")

        token = resp_data.split("=")[1]

        gcm_credentials = AppCredentialsGcm(
            token=token,
            app_id=app_id,
            android_id=checkin_result.android_id,
            security_token=checkin_result.security_token,
            installation=installation_result,
        )

        logger.debug(f"Gcm register return data {gcm_credentials}")

        return gcm_credentials

    async def register(
        self,
        sender_id: str | int,
        app_id: str,
        api_key: str,
        firebase_project_id: str,
        android_cert: str = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        app_name: str = "org.chromium.linux",
        retries: int = 5,
    ) -> AppCredentials:
        """
        Registers a device in GCM and FCM.

        Firebase installation is optional and can be skipped if parameters are not provided.

        FCM subscription may contain `AppCredentials.fcm.error` if not compatible.

        Args:
            sender_id (int | str): sender_id, required
            app_id (str): app_id in the form of "1:123123:android"
            api_key (str): api_key in the form of "AIzaSy..."
            firebase_project_id (str): firebase project name
            android_cert (str): android cert hash as a base64 string
            app_name (str): package name, "org.chromium.linux" by default
            retries (int): number of failed requests before giving up

        Returns:
            GCM and FCM data and keys.
            If fcm registration fails,`AppCredentialsGcm.fcm.error`
            will contain a PullkinResponseError with more details.
        """
        current_retry = 0
        errors: list[PullkinResponseError] = []

        while current_retry < retries:
            try:
                gcm = await self.gcm_register(
                    sender_id=str(sender_id),
                    app_id=app_id,
                    api_key=api_key,
                    firebase_project_id=firebase_project_id,
                    android_cert=android_cert,
                    app_name=app_name,
                    retries=retries,
                )
                logger.debug(f"GCM subscription data: {gcm}")

                if gcm.installation is not None:
                    keys, fcm = await self.fcm_register(
                        gcm_token=gcm.token,
                        api_key=api_key,
                        firebase_project_id=firebase_project_id,
                        firebase_installation=gcm.installation,
                        retries=retries,
                    )
                else:
                    keys = fcm = None

                logger.debug(f"FCM subscription data: {fcm}")

                return AppCredentials(
                    gcm=gcm,
                    fcm=fcm,
                    keys=keys,
                )
            except PullkinResponseError as e:
                current_retry += 1
                logger.error(f"Failed to register: {e}")
                errors.append(e)
                continue

        raise PullkinRegistrationRetriesError(
            f"Failed to register after {retries} retries", errors
        )

    @classmethod
    def _encode_varint32(cls, x):
        res = bytearray([])
        while x != 0:
            b = x & 0x7F
            x >>= 7
            if x != 0:
                b |= 0x80
            res.append(b)
        return bytes(res)

    @classmethod
    def _app_data_by_key(cls, p, key, blow_shit_up=True):
        for x in p.app_data:
            if x.key == key:
                return x.value
        if blow_shit_up:
            raise RuntimeError("couldn't find in app_data {}".format(key))
        return None

    @classmethod
    def _is_deleted_message(cls, p):
        for x in p.app_data:
            if x.key == "message_type" and x.value == "deleted_messages":
                return True
        return False
