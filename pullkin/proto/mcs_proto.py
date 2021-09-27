# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: mcs.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import List

import betterproto


class ClientEventType(betterproto.Enum):
    UNKNOWN = 0
    DISCARDED_EVENTS = 1
    FAILED_CONNECTION = 2
    SUCCESSFUL_CONNECTION = 3


class LoginRequestAuthService(betterproto.Enum):
    ANDROID_ID = 2


class IqStanzaIqType(betterproto.Enum):
    GET = 0
    SET = 1
    RESULT = 2
    IQ_ERROR = 3


@dataclass
class HeartbeatPing(betterproto.Message):
    """*TAG: 0"""

    stream_id: int = betterproto.int32_field(1)
    last_stream_id_received: int = betterproto.int32_field(2)
    status: int = betterproto.int64_field(3)


@dataclass
class HeartbeatAck(betterproto.Message):
    """*TAG: 1"""

    stream_id: int = betterproto.int32_field(1)
    last_stream_id_received: int = betterproto.int32_field(2)
    status: int = betterproto.int64_field(3)


@dataclass
class ErrorInfo(betterproto.Message):
    code: int = betterproto.int32_field(1)
    message: str = betterproto.string_field(2)
    type: str = betterproto.string_field(3)
    extension: "Extension" = betterproto.message_field(4)


@dataclass
class Setting(betterproto.Message):
    name: str = betterproto.string_field(1)
    value: str = betterproto.string_field(2)


@dataclass
class HeartbeatStat(betterproto.Message):
    ip: str = betterproto.string_field(1)
    timeout: bool = betterproto.bool_field(2)
    interval_ms: int = betterproto.int32_field(3)


@dataclass
class HeartbeatConfig(betterproto.Message):
    upload_stat: bool = betterproto.bool_field(1)
    ip: str = betterproto.string_field(2)
    interval_ms: int = betterproto.int32_field(3)


@dataclass
class ClientEvent(betterproto.Message):
    """
    ClientEvents are used to inform the server of failed and successful
    connections.
    """

    # Common fields [1-99]
    type: "ClientEventType" = betterproto.enum_field(1)
    # Fields for DISCARDED_EVENTS messages [100-199]
    number_discarded_events: int = betterproto.uint32_field(100)
    # Fields for FAILED_CONNECTION and SUCCESSFUL_CONNECTION messages [200-299]
    # Network type is a value in net::NetworkChangeNotifier::ConnectionType.
    network_type: int = betterproto.int32_field(200)
    time_connection_started_ms: int = betterproto.uint64_field(202)
    time_connection_ended_ms: int = betterproto.uint64_field(203)
    # Error code should be a net::Error value.
    error_code: int = betterproto.int32_field(204)
    # Fields for SUCCESSFUL_CONNECTION messages [300-399]
    time_connection_established_ms: int = betterproto.uint64_field(300)


@dataclass
class LoginRequest(betterproto.Message):
    """*TAG: 2"""

    id: str = betterproto.string_field(1)
    # string. mcs.android.com.
    domain: str = betterproto.string_field(2)
    # Decimal android ID
    user: str = betterproto.string_field(3)
    resource: str = betterproto.string_field(4)
    # Secret
    auth_token: str = betterproto.string_field(5)
    # Format is: android-HEX_DEVICE_ID The user is the decimal value.
    device_id: str = betterproto.string_field(6)
    # RMQ1 - no longer used
    last_rmq_id: int = betterproto.int64_field(7)
    setting: List["Setting"] = betterproto.message_field(8)
    # optional int32 compress = 9;
    received_persistent_id: List[str] = betterproto.string_field(10)
    adaptive_heartbeat: bool = betterproto.bool_field(12)
    heartbeat_stat: "HeartbeatStat" = betterproto.message_field(13)
    # Must be true.
    use_rmq2: bool = betterproto.bool_field(14)
    account_id: int = betterproto.int64_field(15)
    # ANDROID_ID = 2
    auth_service: "LoginRequestAuthService" = betterproto.enum_field(16)
    network_type: int = betterproto.int32_field(17)
    status: int = betterproto.int64_field(18)
    # Events recorded on the client after the last successful connection.
    client_event: List["ClientEvent"] = betterproto.message_field(22)


@dataclass
class LoginResponse(betterproto.Message):
    """* TAG: 3"""

    id: str = betterproto.string_field(1)
    # Not used.
    jid: str = betterproto.string_field(2)
    # Null if login was ok.
    error: "ErrorInfo" = betterproto.message_field(3)
    setting: List["Setting"] = betterproto.message_field(4)
    stream_id: int = betterproto.int32_field(5)
    # Should be "1"
    last_stream_id_received: int = betterproto.int32_field(6)
    heartbeat_config: "HeartbeatConfig" = betterproto.message_field(7)
    # used by the client to synchronize with the server timestamp.
    server_timestamp: int = betterproto.int64_field(8)


@dataclass
class StreamErrorStanza(betterproto.Message):
    type: str = betterproto.string_field(1)
    text: str = betterproto.string_field(2)


@dataclass
class Close(betterproto.Message):
    """* TAG: 4"""

    pass


@dataclass
class Extension(betterproto.Message):
    # 12: SelectiveAck 13: StreamAck
    id: int = betterproto.int32_field(1)
    data: bytes = betterproto.bytes_field(2)


@dataclass
class IqStanza(betterproto.Message):
    """
    * TAG: 7 IqRequest must contain a single extension.  IqResponse may contain
    0 or 1 extensions.
    """

    rmq_id: int = betterproto.int64_field(1)
    type: "IqStanzaIqType" = betterproto.enum_field(2)
    id: str = betterproto.string_field(3)
    from_: str = betterproto.string_field(4)
    to: str = betterproto.string_field(5)
    error: "ErrorInfo" = betterproto.message_field(6)
    # Only field used in the 38+ protocol (besides common
    # last_stream_id_received, status, rmq_id)
    extension: "Extension" = betterproto.message_field(7)
    persistent_id: str = betterproto.string_field(8)
    stream_id: int = betterproto.int32_field(9)
    last_stream_id_received: int = betterproto.int32_field(10)
    account_id: int = betterproto.int64_field(11)
    status: int = betterproto.int64_field(12)


@dataclass
class AppData(betterproto.Message):
    key: str = betterproto.string_field(1)
    value: str = betterproto.string_field(2)


@dataclass
class DataMessageStanza(betterproto.Message):
    """* TAG: 8"""

    # This is the message ID, set by client, DMP.9 (message_id)
    id: str = betterproto.string_field(2)
    # Project ID of the sender, DMP.1
    from_: str = betterproto.string_field(3)
    # Part of DMRequest - also the key in DataMessageProto.
    to: str = betterproto.string_field(4)
    # Package name. DMP.2
    category: str = betterproto.string_field(5)
    # The collapsed key, DMP.3
    token: str = betterproto.string_field(6)
    # User data + GOOGLE. prefixed special entries, DMP.4
    app_data: List["AppData"] = betterproto.message_field(7)
    # Not used.
    from_trusted_server: bool = betterproto.bool_field(8)
    # Part of the ACK protocol, returned in DataMessageResponse on server side.
    # It's part of the key of DMP.
    persistent_id: str = betterproto.string_field(9)
    # In-stream ack. Increments on each message sent - a bit redundant Not used
    # in DMP/DMR.
    stream_id: int = betterproto.int32_field(10)
    last_stream_id_received: int = betterproto.int32_field(11)
    # Sent by the device shortly after registration.
    reg_id: str = betterproto.string_field(13)
    # serial number of the target user, DMP.8 It is the 'serial number' according
    # to user manager.
    device_user_id: int = betterproto.int64_field(16)
    # Time to live, in seconds.
    ttl: int = betterproto.int32_field(17)
    # Timestamp ( according to client ) when message was sent by app, in seconds
    sent: int = betterproto.int64_field(18)
    # How long has the message been queued before the flush, in seconds. This is
    # needed to account for the time difference between server and client: server
    # should adjust 'sent' based on its 'receive' time.
    queued: int = betterproto.int32_field(19)
    status: int = betterproto.int64_field(20)
    # Optional field containing the binary payload of the message.
    raw_data: bytes = betterproto.bytes_field(21)
    # If set the server requests immediate ack. Used for important messages and
    # for testing.
    immediate_ack: bool = betterproto.bool_field(24)


@dataclass
class StreamAck(betterproto.Message):
    """
    *Included in IQ with ID 13, sent from client or server after 10
    unconfirmedmessages.
    """

    pass


@dataclass
class SelectiveAck(betterproto.Message):
    """*Included in IQ sent after LoginResponse from server with ID 12."""

    id: List[str] = betterproto.string_field(1)
