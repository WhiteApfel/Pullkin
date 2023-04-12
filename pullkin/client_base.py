import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from base64 import urlsafe_b64encode
from typing import Optional, Union
from urllib.parse import urlencode

from httpx import AsyncClient, Request
from loguru import logger
from oscrypto.asymmetric import generate_pair

from pullkin.models import AppCredentials, AppCredentialsGcm
from pullkin.models.credentials import FirebaseInstallationResponse
from pullkin.proto.android_checkin_proto import AndroidCheckinProto, ChromeBuildProto
from pullkin.proto.checkin_proto import AndroidCheckinRequest, AndroidCheckinResponse
from pullkin.proto.mcs_proto import *  # noqa: F403

logger.disable("pullkin")


class PullkinBase:
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
    FCM_INSTALLATION_URL_PATTERN = (
        "https://firebaseinstallations.googleapis.com/v1/projects/{}/installations"
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
        self.credentials: Optional[AppCredentials] = None
        self.apps: dict[dict[str, AppCredentials | list[str]]] = {}

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
    def generate_fid(cls) -> str:
        fid_byte_array = bytearray(17)
        fid_byte_array[:] = secrets.token_bytes(17)

        # Replace the first 4 random bits with the constant FID header of 0b0111.
        fid_byte_array[0] = 0b01110000 + (fid_byte_array[0] % 0b00010000)

        b64 = base64.b64encode(fid_byte_array).decode("utf-8")
        b64_safe = b64.replace("+", "-").replace("/", "_")
        fid = b64_safe[:22]
        return fid

    async def _do_request(self, req, retries=5):
        for _ in range(retries):
            try:
                resp = await self.http_client.send(req, follow_redirects=True)
                resp_data = resp.content
                logger.debug(f"Response:\n{resp_data}")
                return resp_data
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
        firebase_name: str,
    ) -> FirebaseInstallationResponse:
        data = {
            "fid": self.generate_fid(),
            "authVersion": "FIS_v2",
            "app_id": app_id,
            "sdkVersion": "a:17.1.0",
        }
        headers = {
            "x-goog-api-key": api_key,
            "x-android-cert": android_cert,
            "x-android-package": app_package,
        }

        req = self.http_client.build_request(
            method="POST",
            url=self.FCM_INSTALLATION_URL_PATTERN.format(firebase_name),
            headers=headers,
            json=data,
            timeout=5,
        )
        resp = await self._do_request(req)

        resp_data = json.loads(resp.decode("utf-8"))

        return FirebaseInstallationResponse(
            name=resp_data["name"],
            fid=resp_data["fid"],
            refresh_token=resp_data["refreshToken"],
            auth_token=resp_data["authToken"]["token"],
            auth_token_expires_in=int(resp_data["authToken"]["expiresIn"][:-1]),
        )

    async def gcm_check_in(
        self, credentials: Optional[AppCredentialsGcm] = None
    ) -> AndroidCheckinResponse:
        """
        perform check-in request

        android_id, security_token can be provided if we already did the initial
        check-in

        returns dict with android_id, security_token and more
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

        logger.debug(f"Payload:\n{payload}")
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
        logger.debug(f"Response:\n{resp}")
        return resp

    @classmethod
    def urlsafe_base64(cls, data):
        """
        base64-encodes data with -_ instead of +/ and removes all = padding.
        also strips newlines

        returns a string
        """
        res = urlsafe_b64encode(data).replace(b"=", b"")
        return res.replace(b"\n", b"").decode("ascii")

    async def gcm_register(
        self,
        sender_id: str,
        app_id: str,
        api_key: str,
        android_cert,
        app_name: str,
        firebase_name: str,
        retries=5,
        **_,
    ):
        """
        obtains a gcm token

        app_id: app id as an integer
        retries: number of failed requests before giving up

        returns {"token": "...", "app_id": 123123, "android_id":123123,
                 "security_token": 123123}
        """
        # contains android_id, security_token and more
        checkin_result = await self.gcm_check_in()
        installation_result = await self.fcm_installation(
            app_id, api_key, android_cert, app_name, firebase_name
        )
        logger.debug(f"Check_in:\n{checkin_result}")
        body = {
            "X-subtype": sender_id,
            "sender": sender_id,
            "X-app_ver": "1111",
            "X-osv": "25",
            "X-cliv": "fcm-23.1.1",
            "X-gmsv": "231114044",
            "X-appid": installation_result.fid,
            "X-scope": "*",
            "X-Goog-Firebase-Installations-Auth": installation_result.auth_token,
            "X-gmp_app_id": app_id,
            "X-firebase-app-name-hash": (
                base64.b64encode(hashlib.sha1(app_name.encode()).digest())
                .decode("utf-8")
                .rstrip("=")
            ),
            "X-app_ver_name": "1.1.1.1",
            "app": app_name,
            "device": checkin_result.android_id,
            "app_ver": "1111",
            "gcm_ver": "231114044",
            "plat": "0",
            "cert": android_cert,
            "target_ver": "28",
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
        for _ in range(retries):
            resp_data = await self._do_request(req, retries)

            if b"Error" in resp_data:
                err = resp_data.decode("utf-8")
                logger.error(f"Register request has failed with {err}")
                continue
            token = resp_data.decode("utf-8").split("=")[1]

            gcm_credentials = AppCredentialsGcm(
                token=token,
                app_id=app_id,
                android_id=checkin_result.android_id,
                security_token=checkin_result.security_token,
                installation=installation_result,
            )

            logger.debug(f"Gcm register return data {gcm_credentials}")

            return gcm_credentials
        raise ValueError("Register error")

    async def fcm_register(self, sender_id: Union[str, int], token, retries=5):
        """
        generates key pair and obtains a fcm token

        sender_id: sender id as an integer
        token: the subscription token in the dict returned by gcm_register

        returns {"keys": keys, "fcm": {...}}
        """
        # I used this analyzer to figure out how to slice the asn1 structs
        # https://lapo.it/asn1js
        # first byte of public key is skipped for some reason
        # maybe it's always zero
        public, private = generate_pair("ec", curve=self.unicode("secp256r1"))
        from base64 import b64encode

        logger.debug("# Public")
        logger.debug(b64encode(public.asn1.dump()))
        logger.debug("# Private")
        logger.debug(b64encode(private.asn1.dump()))
        keys = {
            "public": self.urlsafe_base64(public.asn1.dump()[26:]),
            "private": self.urlsafe_base64(private.asn1.dump()),
            "secret": self.urlsafe_base64(os.urandom(16)),
        }
        body = {
            "authorized_entity": int(sender_id),
            "endpoint": "{}/{}".format(self.FCM_ENDPOINT, token),
            "encryption_key": keys["public"],
            "encryption_auth": keys["secret"],
        }
        logger.debug(f"Data:\n{body}")
        req = Request(method="POST", url=self.FCM_SUBSCRIBE, data=body)
        resp_data = await self._do_request(req, retries)
        return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}

    async def register(
        self,
        sender_id: Union[str, int],
        app_id: str,
        api_key: str,
        firebase_name: str,
        android_cert: str = 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        app_name: str = "org.chromium.linux",
    ) -> AppCredentials:
        """register gcm and fcm tokens for sender_id"""
        gcm_result = await self.gcm_register(
            sender_id=str(sender_id),
            app_id=app_id,
            api_key=api_key,
            android_cert=android_cert,
            app_name=app_name,
            firebase_name=firebase_name,
        )
        logger.debug(f"GCM subscription data: {gcm_result}")
        fcm = await self.fcm_register(sender_id=sender_id, token=gcm_result.token)
        logger.debug(f"FCM subscription data: {fcm}")
        res = {"gcm": gcm_result}
        res.update(fcm)

        self.apps.setdefault(
            str(sender_id), {"credentials": None, "persistent_ids": []}
        )
        self.apps[str(sender_id)]["credentials"] = AppCredentials(**res)
        return self.apps[str(sender_id)]["credentials"]

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
