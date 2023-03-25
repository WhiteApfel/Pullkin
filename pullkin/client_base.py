import asyncio
import json
import os
import time
from base64 import urlsafe_b64encode
from typing import Optional, Union
from urllib.parse import urlencode

from httpx import AsyncClient, Request
from loguru import logger
from oscrypto.asymmetric import generate_pair

from pullkin.models import AppCredentials, AppCredentialsGcm
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

    REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
    CHECKIN_URL = "https://android.clients.google.com/checkin"
    FCM_SUBSCRIBE = "https://fcm.googleapis.com/fcm/connect/subscribe"
    FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send"

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

    @property
    def http_client(self):
        if not self._http_client:
            self._http_client = AsyncClient()
        return self._http_client

    async def close(self):
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

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

    async def gcm_check_in(self, credentials: Optional[AppCredentialsGcm] = None):
        """
        perform check-in request

        androidId, securityToken can be provided if we already did the initial
        check-in

        returns dict with androidId, securityToken and more
        """
        chrome = ChromeBuildProto()
        chrome.platform = 3
        chrome.chrome_version = "63.0.3234.0"
        chrome.channel = 1

        checkin = AndroidCheckinProto()
        checkin.type = 3
        checkin.chrome_build.from_dict(chrome.to_dict())

        payload = AndroidCheckinRequest()
        payload.user_serial_number = 0
        payload.checkin.from_dict(checkin.to_dict())
        payload.version = 3
        if credentials:
            payload.id = int(credentials.androidId)
            payload.security_token = int(credentials.securityToken)

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
        return resp.to_dict()

    @classmethod
    def urlsafe_base64(cls, data):
        """
        base64-encodes data with -_ instead of +/ and removes all = padding.
        also strips newlines

        returns a string
        """
        res = urlsafe_b64encode(data).replace(b"=", b"")
        return res.replace(b"\n", b"").decode("ascii")

    async def gcm_register(self, app_id, retries=5, **_):
        """
        obtains a gcm token

        appId: app id as an integer
        retries: number of failed requests before giving up

        returns {"token": "...", "appId": 123123, "androidId":123123,
                 "securityToken": 123123}
        """
        # contains androidId, securityToken and more
        chk = await self.gcm_check_in()
        logger.debug(f"Check_in:\n{chk}")
        body = {
            "app": "org.chromium.linux",
            "X-subtype": app_id,
            "device": chk["androidId"],
            "sender": self.urlsafe_base64(self.SERVER_KEY),
        }
        data = urlencode(body)
        logger.debug(f"Data:\n{data}")
        auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
        req = Request(
            method="POST",
            url=self.REGISTER_URL,
            headers={"Authorization": auth},
            data=body,
        )
        for _ in range(retries):
            resp_data = await self._do_request(req, retries)
            if b"Error" in resp_data:
                err = resp_data.decode("utf-8")
                logger.error(f"Register request has failed with {err}")
                continue
            token = resp_data.decode("utf-8").split("=")[1]
            chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
            res = {"token": token, "appId": app_id}
            res.update(chkfields)
            return res
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

    async def register(self, sender_id: Union[str, int], app_id: str) -> AppCredentials:
        """register gcm and fcm tokens for sender_id"""
        subscription = await self.gcm_register(app_id=app_id)
        logger.debug(f"GCM subscription data: {subscription}")
        fcm = await self.fcm_register(sender_id=sender_id, token=subscription["token"])
        logger.debug(f"FCM subscription data: {fcm}")
        res = {"gcm": subscription}
        res.update(fcm)

        self.credentials = AppCredentials(**res)
        return AppCredentials(**res)

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
