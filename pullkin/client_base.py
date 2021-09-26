import json
import logging
import os
import time
import uuid
from base64 import urlsafe_b64encode
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from google.protobuf.json_format import MessageToDict
from oscrypto.asymmetric import generate_pair

from .android_checkin_pb2 import AndroidCheckinProto, ChromeBuildProto
from .checkin_pb2 import AndroidCheckinRequest, AndroidCheckinResponse
from .mcs_pb2 import *


class PullkinBase:
    unicode = str

    __log = logging.getLogger("pullkin")

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

    @classmethod
    def __do_request(cls, req, retries=5):
        for _ in range(retries):
            try:
                resp = urlopen(req)
                resp_data = resp.read()
                resp.close()
                cls.__log.debug(resp_data)
                return resp_data
            except Exception as e:
                cls.__log.debug("error during request", exc_info=e)
                time.sleep(1)
        return None

    @classmethod
    def gcm_check_in(cls, androidId=None, securityToken=None, **_):
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
        checkin.chrome_build.CopyFrom(chrome)

        payload = AndroidCheckinRequest()
        payload.user_serial_number = 0
        payload.checkin.CopyFrom(checkin)
        payload.version = 3
        if androidId:
            payload.id = int(androidId)
        if securityToken:
            payload.security_token = int(securityToken)

        cls.__log.debug(payload)
        req = Request(
            url=cls.CHECKIN_URL,
            headers={"Content-Type": "application/x-protobuf"},
            data=payload.SerializeToString(),
        )
        resp_data = cls.__do_request(req)
        resp = AndroidCheckinResponse()
        resp.ParseFromString(resp_data)
        cls.__log.debug(resp)
        return MessageToDict(resp)

    @classmethod
    def urlsafe_base64(cls, data):
        """
        base64-encodes data with -_ instead of +/ and removes all = padding.
        also strips newlines

        returns a string
        """
        res = urlsafe_b64encode(data).replace(b"=", b"")
        return res.replace(b"\n", b"").decode("ascii")

    @classmethod
    def gcm_register(cls, appId, retries=5, **_):
        """
        obtains a gcm token

        appId: app id as an integer
        retries: number of failed requests before giving up

        returns {"token": "...", "appId": 123123, "androidId":123123,
                 "securityToken": 123123}
        """
        # contains androidId, securityToken and more
        chk = cls.gcm_check_in()
        cls.__log.debug(chk)
        body = {
            "app": "org.chromium.linux",
            "X-subtype": appId,
            "device": chk["androidId"],
            "sender": cls.urlsafe_base64(cls.SERVER_KEY),
        }
        data = urlencode(body)
        cls.__log.debug(data)
        auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
        req = Request(
            url=cls.REGISTER_URL,
            headers={"Authorization": auth},
            data=data.encode("utf-8"),
        )
        for _ in range(retries):
            resp_data = cls.__do_request(req, retries)
            if b"Error" in resp_data:
                err = resp_data.decode("utf-8")
                cls.__log.error("Register request has failed with " + err)
                continue
            token = resp_data.decode("utf-8").split("=")[1]
            chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
            res = {"token": token, "appId": appId}
            res.update(chkfields)
            return res
        return None

    @classmethod
    def fcm_register(cls, sender_id, token, retries=5):
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
        public, private = generate_pair("ec", curve=cls.unicode("secp256r1"))
        from base64 import b64encode

        cls.__log.debug("# public")
        cls.__log.debug(b64encode(public.asn1.dump()))
        cls.__log.debug("# private")
        cls.__log.debug(b64encode(private.asn1.dump()))
        keys = {
            "public": cls.urlsafe_base64(public.asn1.dump()[26:]),
            "private": cls.urlsafe_base64(private.asn1.dump()),
            "secret": cls.urlsafe_base64(os.urandom(16)),
        }
        data = urlencode(
            {
                "authorized_entity": sender_id,
                "endpoint": "{}/{}".format(cls.FCM_ENDPOINT, token),
                "encryption_key": keys["public"],
                "encryption_auth": keys["secret"],
            }
        )
        cls.__log.debug(data)
        req = Request(url=cls.FCM_SUBSCRIBE, data=data.encode("utf-8"))
        resp_data = cls.__do_request(req, retries)
        return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}

    @classmethod
    def register(cls, sender_id):
        """register gcm and fcm tokens for sender_id"""
        app_id = "wp:receiver.push.com#{}".format(uuid.uuid4())
        subscription = cls.gcm_register(appId=app_id)
        cls.__log.debug(subscription)
        fcm = cls.fcm_register(sender_id=sender_id, token=subscription["token"])
        cls.__log.debug(fcm)
        res = {"gcm": subscription}
        res.update(fcm)
        return res

    @classmethod
    def __encode_varint32(cls, x):
        res = bytearray([])
        while x != 0:
            b = x & 0x7F
            x >>= 7
            if x != 0:
                b |= 0x80
            res.append(b)
        return bytes(res)

    @classmethod
    def __app_data_by_key(cls, p, key, blow_shit_up=True):
        for x in p.app_data:
            if x.key == key:
                return x.value
        if blow_shit_up:
            raise RuntimeError("couldn't find in app_data {}".format(key))
        return None
