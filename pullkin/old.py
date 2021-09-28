import asyncio
import inspect
import json
import logging
import os
import struct
import time
import uuid
from asyncio import StreamReader, StreamWriter
from base64 import urlsafe_b64decode, urlsafe_b64encode
from binascii import hexlify
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from loguru import logger
from oscrypto.asymmetric import generate_pair

from pullkin.proto.android_checkin_proto import AndroidCheckinProto, ChromeBuildProto
from pullkin.proto.checkin_proto import AndroidCheckinRequest, AndroidCheckinResponse
from pullkin.proto.mcs_proto import *

unicode = str

logger.disable("pullkin")

SERVER_KEY = (
    b"\x04\x33\x94\xf7\xdf\xa1\xeb\xb1\xdc\x03\xa2\x5e\x15\x71\xdb\x48\xd3"
    + b"\x2e\xed\xed\xb2\x34\xdb\xb7\x47\x3a\x0c\x8f\xc4\xcc\xe1\x6f\x3c"
    + b"\x8c\x84\xdf\xab\xb6\x66\x3e\xf2\x0c\xd4\x8b\xfe\xe3\xf9\x76\x2f"
    + b"\x14\x1c\x63\x08\x6a\x6f\x2d\xb1\x1a\x95\xb0\xce\x37\xc0\x9c\x6e"
)

REGISTER_URL = "https://android.clients.google.com/c2dm/register3"
CHECKIN_URL = "https://android.clients.google.com/checkin"
FCM_SUBSCRIBE = "https://fcm.googleapis.com/fcm/connect/subscribe"
FCM_ENDPOINT = "https://fcm.googleapis.com/fcm/send"


def __do_request(req, retries=5):
    for _ in range(retries):
        try:
            resp = urlopen(req)
            resp_data = resp.read()
            resp.close()
            logger.debug(resp_data)
            return resp_data
        except Exception as e:
            logger.debug("error during request", exc_info=e)
            time.sleep(1)
    return None


def gcm_check_in(androidId=None, securityToken=None, **_):
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
    if androidId:
        payload.id = int(androidId)
    if securityToken:
        payload.security_token = int(securityToken)

    logger.debug(payload)
    req = Request(
        url=CHECKIN_URL,
        headers={"Content-Type": "application/x-protobuf"},
        data=payload.SerializeToString(),
    )
    resp_data = __do_request(req)
    resp = AndroidCheckinResponse()
    resp.parse(resp_data)
    logger.debug(resp)
    return resp.to_dict()


def urlsafe_base64(data):
    """
    base64-encodes data with -_ instead of +/ and removes all = padding.
    also strips newlines

    returns a string
    """
    res = urlsafe_b64encode(data).replace(b"=", b"")
    return res.replace(b"\n", b"").decode("ascii")


def gcm_register(appId, retries=5, **_):
    """
    obtains a gcm token

    appId: app id as an integer
    retries: number of failed requests before giving up

    returns {"token": "...", "appId": 123123, "androidId":123123,
             "securityToken": 123123}
    """
    # contains androidId, securityToken and more
    chk = gcm_check_in()
    logger.debug(chk)
    body = {
        "app": "org.chromium.linux",
        "X-subtype": appId,
        "device": chk["androidId"],
        "sender": urlsafe_base64(SERVER_KEY),
    }
    data = urlencode(body)
    logger.debug(data)
    auth = "AidLogin {}:{}".format(chk["androidId"], chk["securityToken"])
    req = Request(
        url=REGISTER_URL, headers={"Authorization": auth}, data=data.encode("utf-8")
    )
    for _ in range(retries):
        resp_data = __do_request(req, retries)
        if b"Error" in resp_data:
            err = resp_data.decode("utf-8")
            logger.error("Register request has failed with " + err)
            continue
        token = resp_data.decode("utf-8").split("=")[1]
        chkfields = {k: chk[k] for k in ["androidId", "securityToken"]}
        res = {"token": token, "appId": appId}
        res.update(chkfields)
        return res
    return None


def fcm_register(sender_id, token, retries=5):
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
    public, private = generate_pair("ec", curve=unicode("secp256r1"))
    from base64 import b64encode

    logger.debug("# public")
    logger.debug(b64encode(public.asn1.dump()))
    logger.debug("# private")
    logger.debug(b64encode(private.asn1.dump()))
    keys = {
        "public": urlsafe_base64(public.asn1.dump()[26:]),
        "private": urlsafe_base64(private.asn1.dump()),
        "secret": urlsafe_base64(os.urandom(16)),
    }
    data = urlencode(
        {
            "authorized_entity": sender_id,
            "endpoint": "{}/{}".format(FCM_ENDPOINT, token),
            "encryption_key": keys["public"],
            "encryption_auth": keys["secret"],
        }
    )
    logger.debug(data)
    req = Request(url=FCM_SUBSCRIBE, data=data.encode("utf-8"))
    resp_data = __do_request(req, retries)
    return {"keys": keys, "fcm": json.loads(resp_data.decode("utf-8"))}


def register(sender_id):
    """register gcm and fcm tokens for sender_id"""
    app_id = "wp:receiver.push.com#{}".format(uuid.uuid4())
    subscription = gcm_register(appId=app_id)
    logger.debug(subscription)
    fcm = fcm_register(sender_id=sender_id, token=subscription["token"])
    logger.debug(fcm)
    res = {"gcm": subscription}
    res.update(fcm)
    return res


# -------------------------------------------------------------------------


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


def __read(s, size):
    buf = b""
    while len(buf) < size:
        buf += s.recv(size - len(buf))
    return buf


async def __aioread(reader: StreamReader, size):
    buf = b""
    while len(buf) < size:
        buf += await reader.read(size - len(buf))
    return buf


# protobuf variable length integers are encoded in base 128
# each byte contains 7 bits of the integer and the msb is set if there's
# more. pretty simple to implement


def __read_varint32(s):
    res = 0
    shift = 0
    while True:
        (b,) = struct.unpack("B", __read(s, 1))
        res |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return res


async def __aioread_varint32(reader: StreamReader):
    res = 0
    shift = 0
    while True:
        (b,) = struct.unpack("B", await __aioread(reader, 1))
        res |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return res


def __encode_varint32(x):
    res = bytearray([])
    while x != 0:
        b = x & 0x7F
        x >>= 7
        if x != 0:
            b |= 0x80
        res.append(b)
    return bytes(res)


def __send(s, packet):
    header = bytearray([MCS_VERSION, PACKET_BY_TAG.index(type(packet))])
    logger.debug(packet)
    payload = packet.SerializeToString()
    buf = bytes(header) + __encode_varint32(len(payload)) + payload
    logger.debug(hexlify(buf))
    n = len(buf)
    total = 0
    while total < n:
        sent = s.send(buf[total:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        total += sent


async def __aiosend(writer: StreamWriter, packet):
    header = bytearray([MCS_VERSION, PACKET_BY_TAG.index(type(packet))])
    logger.debug(packet)
    payload = packet.SerializeToString()
    buf = bytes(header) + __encode_varint32(len(payload)) + payload
    logger.debug(hexlify(buf))
    writer.write(buf)
    await writer.drain()


def __recv(s, first=False):
    if first:
        version, tag = struct.unpack("BB", __read(s, 2))
        logger.debug("version {}".format(version))
        if version < MCS_VERSION and version != 38:
            raise RuntimeError("protocol version {} unsupported".format(version))
    else:
        (tag,) = struct.unpack("B", __read(s, 1))
    logger.debug("tag {} ({})".format(tag, PACKET_BY_TAG[tag]))
    size = __read_varint32(s)
    logger.debug("size {}".format(size))
    if size >= 0:
        buf = __read(s, size)
        logger.debug(hexlify(buf))
        packet_class = PACKET_BY_TAG[tag]
        payload = packet_class()
        payload.parse(buf)
        logger.debug(payload)
        return payload
    return None


async def __aiorecv(reader: StreamReader, first=False):
    if first:
        version, tag = struct.unpack("BB", await __aioread(reader, 2))
        logger.debug("version {}".format(version))
        if version < MCS_VERSION and version != 38:
            raise RuntimeError("protocol version {} unsupported".format(version))
    else:
        (tag,) = struct.unpack("B", await __aioread(reader, 1))
    logger.debug("tag {} ({})".format(tag, PACKET_BY_TAG[tag]))
    size = await __aioread_varint32(reader)
    logger.debug("size {}".format(size))
    if size >= 0:
        buf = await __aioread(reader, size)
        logger.debug(hexlify(buf))
        packet_class = PACKET_BY_TAG[tag]
        payload = packet_class()
        payload.parse(buf)
        logger.debug(payload)
        return payload
    return None


def __app_data_by_key(p, key, blow_shit_up=True):
    for x in p.app_data:
        if x.key == key:
            return x.value
    if blow_shit_up:
        raise RuntimeError("couldn't find in app_data {}".format(key))
    return None


def __listen(s, credentials, callback, persistent_ids, obj, timer=0, is_alive=True):
    import cryptography.hazmat.primitives.serialization as serialization
    import http_ece
    from cryptography.hazmat.backends import default_backend

    load_der_private_key = serialization.load_der_private_key

    gcm_check_in(**credentials["gcm"])
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
    req.setting.append(Setting(name="new_vc", value="1"))
    req.received_persistent_id.extend(persistent_ids)
    __send(s, req)
    __recv(s, first=True)
    while is_alive:
        p = __recv(s)
        if type(p) is not DataMessageStanza:
            continue
        crypto_key = __app_data_by_key(p, "crypto-key")[3:]  # strip dh=
        salt = __app_data_by_key(p, "encryption")[5:]  # strip salt=
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
            asyncio.run(callback(obj, json.loads(decrypted.decode("utf-8")), p))
        else:
            callback(obj, json.loads(decrypted.decode("utf-8")), p)
        if timer:
            time.sleep(timer)


async def __aiolisten(
    reader, writer, credentials, callback, persistent_ids, obj, timer=0, is_alive=True
):
    import cryptography.hazmat.primitives.serialization as serialization
    import http_ece
    from cryptography.hazmat.backends import default_backend

    load_der_private_key = serialization.load_der_private_key

    gcm_check_in(**credentials["gcm"])
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
    req.setting.append(Setting(name="new_vc", value="1"))
    req.received_persistent_id.extend(persistent_ids)
    await __aiosend(writer, req)
    await __aiorecv(reader, first=True)
    while is_alive:
        p = await __aiorecv(reader)
        if type(p) is not DataMessageStanza:
            continue
        crypto_key = __app_data_by_key(p, "crypto-key")[3:]  # strip dh=
        salt = __app_data_by_key(p, "encryption")[5:]  # strip salt=
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


def listen(
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
    import socket
    import ssl

    host = "mtalk.google.com"
    context = ssl.create_default_context()
    sock = socket.create_connection((host, 5228))
    s = context.wrap_socket(sock, server_hostname=host)
    logger.debug("connected to ssl socket")
    __listen(s, credentials, callback, received_persistent_ids, obj, timer, is_alive)
    s.close()
    sock.close()


async def aiolisten(
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
    logger.debug("connected to ssl socket")
    await __aiolisten(
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


def run_example():
    """sample that registers a token and waits for notifications"""
    import argparse
    import os.path
    import sys

    import appdirs

    parser = argparse.ArgumentParser(description="push_receiver demo")
    parser.add_argument("--sender-id")
    parser.add_argument("--no-listen", action="store_true")
    levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    parser.add_argument("--log", choices=levels)
    args = parser.parse_args(sys.argv[1:])
    logging.basicConfig(level=logging.CRITICAL + 1)
    args.log and logging.getLogger().setLevel(args.log)

    data_path = appdirs.user_data_dir(appname="push_receiver", appauthor="lolisamurai")
    try:
        os.makedirs(data_path)
    except FileExistsError:
        pass
    credentials_path = os.path.join(data_path, "credentials.json")
    persistent_ids_path = os.path.join(data_path, "persistent_ids")

    try:
        with open(credentials_path, "r") as f:
            credentials = json.load(f)

    except FileNotFoundError:
        credentials = register(sender_id=int(args.sender_id))
        with open(credentials_path, "w") as f:
            json.dump(credentials, f)

    logger.debug(credentials)
    print("send notifications to {}".format(credentials["fcm"]["token"]))
    if args.no_listen:
        return

    def on_notification(obj, notification, data_message):
        idstr = data_message.persistent_id + "\n"
        with open(persistent_ids_path, "r") as f:
            if idstr in f:
                return
        with open(persistent_ids_path, "a") as f:
            f.write(idstr)
        n = notification["notification"]
        text = n["title"]
        if n["body"]:
            text += ": " + n["body"]
        print(text)

    with open(persistent_ids_path, "a+") as f:
        received_persistent_ids = [x.strip() for x in f]

    listen(credentials, on_notification, received_persistent_ids)
