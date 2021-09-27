# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: checkin.proto

from pullkin.proto import android_checkin_pb2 as android__checkin__pb2
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import reflection as _reflection
from google.protobuf import message as _message
from google.protobuf import descriptor as _descriptor
import sys

_b = sys.version_info[0] < 3 and (lambda x: x) or (lambda x: x.encode("latin1"))
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor.FileDescriptor(
    name="checkin.proto",
    package="checkin_proto",
    syntax="proto2",
    serialized_options=_b("H\003"),
    serialized_pb=_b(
        '\n\rcheckin.proto\x12\rcheckin_proto\x1a\x15\x61ndroid_checkin.proto"/\n\x10GservicesSetting\x12\x0c\n\x04name\x18\x01 \x02(\x0c\x12\r\n\x05value\x18\x02 \x02(\x0c"\xcb\x03\n\x15\x41ndroidCheckinRequest\x12\x0c\n\x04imei\x18\x01 \x01(\t\x12\x0c\n\x04meid\x18\n \x01(\t\x12\x10\n\x08mac_addr\x18\t \x03(\t\x12\x15\n\rmac_addr_type\x18\x13 \x03(\t\x12\x15\n\rserial_number\x18\x10 \x01(\t\x12\x0b\n\x03\x65sn\x18\x11 \x01(\t\x12\n\n\x02id\x18\x02 \x01(\x03\x12\x12\n\nlogging_id\x18\x07 \x01(\x03\x12\x0e\n\x06\x64igest\x18\x03 \x01(\t\x12\x0e\n\x06locale\x18\x06 \x01(\t\x12\x33\n\x07\x63heckin\x18\x04 \x02(\x0b\x32".checkin_proto.AndroidCheckinProto\x12\x15\n\rdesired_build\x18\x05 \x01(\t\x12\x16\n\x0emarket_checkin\x18\x08 \x01(\t\x12\x16\n\x0e\x61\x63\x63ount_cookie\x18\x0b \x03(\t\x12\x11\n\ttime_zone\x18\x0c \x01(\t\x12\x16\n\x0esecurity_token\x18\r \x01(\x06\x12\x0f\n\x07version\x18\x0e \x01(\x05\x12\x10\n\x08ota_cert\x18\x0f \x03(\t\x12\x10\n\x08\x66ragment\x18\x14 \x01(\x05\x12\x11\n\tuser_name\x18\x15 \x01(\t\x12\x1a\n\x12user_serial_number\x18\x16 \x01(\x05"\x83\x02\n\x16\x41ndroidCheckinResponse\x12\x10\n\x08stats_ok\x18\x01 \x02(\x08\x12\x11\n\ttime_msec\x18\x03 \x01(\x03\x12\x0e\n\x06\x64igest\x18\x04 \x01(\t\x12\x15\n\rsettings_diff\x18\t \x01(\x08\x12\x16\n\x0e\x64\x65lete_setting\x18\n \x03(\t\x12\x30\n\x07setting\x18\x05 \x03(\x0b\x32\x1f.checkin_proto.GservicesSetting\x12\x11\n\tmarket_ok\x18\x06 \x01(\x08\x12\x12\n\nandroid_id\x18\x07 \x01(\x06\x12\x16\n\x0esecurity_token\x18\x08 \x01(\x06\x12\x14\n\x0cversion_info\x18\x0b \x01(\tB\x02H\x03'
    ),
    dependencies=[
        android__checkin__pb2.DESCRIPTOR,
    ],
)


_GSERVICESSETTING = _descriptor.Descriptor(
    name="GservicesSetting",
    full_name="checkin_proto.GservicesSetting",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="name",
            full_name="checkin_proto.GservicesSetting.name",
            index=0,
            number=1,
            type=12,
            cpp_type=9,
            label=2,
            has_default_value=False,
            default_value=_b(""),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="value",
            full_name="checkin_proto.GservicesSetting.value",
            index=1,
            number=2,
            type=12,
            cpp_type=9,
            label=2,
            has_default_value=False,
            default_value=_b(""),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto2",
    extension_ranges=[],
    oneofs=[],
    serialized_start=55,
    serialized_end=102,
)


_ANDROIDCHECKINREQUEST = _descriptor.Descriptor(
    name="AndroidCheckinRequest",
    full_name="checkin_proto.AndroidCheckinRequest",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="imei",
            full_name="checkin_proto.AndroidCheckinRequest.imei",
            index=0,
            number=1,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="meid",
            full_name="checkin_proto.AndroidCheckinRequest.meid",
            index=1,
            number=10,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="mac_addr",
            full_name="checkin_proto.AndroidCheckinRequest.mac_addr",
            index=2,
            number=9,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="mac_addr_type",
            full_name="checkin_proto.AndroidCheckinRequest.mac_addr_type",
            index=3,
            number=19,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="serial_number",
            full_name="checkin_proto.AndroidCheckinRequest.serial_number",
            index=4,
            number=16,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="esn",
            full_name="checkin_proto.AndroidCheckinRequest.esn",
            index=5,
            number=17,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="id",
            full_name="checkin_proto.AndroidCheckinRequest.id",
            index=6,
            number=2,
            type=3,
            cpp_type=2,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="logging_id",
            full_name="checkin_proto.AndroidCheckinRequest.logging_id",
            index=7,
            number=7,
            type=3,
            cpp_type=2,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="digest",
            full_name="checkin_proto.AndroidCheckinRequest.digest",
            index=8,
            number=3,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="locale",
            full_name="checkin_proto.AndroidCheckinRequest.locale",
            index=9,
            number=6,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="checkin",
            full_name="checkin_proto.AndroidCheckinRequest.checkin",
            index=10,
            number=4,
            type=11,
            cpp_type=10,
            label=2,
            has_default_value=False,
            default_value=None,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="desired_build",
            full_name="checkin_proto.AndroidCheckinRequest.desired_build",
            index=11,
            number=5,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="market_checkin",
            full_name="checkin_proto.AndroidCheckinRequest.market_checkin",
            index=12,
            number=8,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="account_cookie",
            full_name="checkin_proto.AndroidCheckinRequest.account_cookie",
            index=13,
            number=11,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="time_zone",
            full_name="checkin_proto.AndroidCheckinRequest.time_zone",
            index=14,
            number=12,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="security_token",
            full_name="checkin_proto.AndroidCheckinRequest.security_token",
            index=15,
            number=13,
            type=6,
            cpp_type=4,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="version",
            full_name="checkin_proto.AndroidCheckinRequest.version",
            index=16,
            number=14,
            type=5,
            cpp_type=1,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="ota_cert",
            full_name="checkin_proto.AndroidCheckinRequest.ota_cert",
            index=17,
            number=15,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="fragment",
            full_name="checkin_proto.AndroidCheckinRequest.fragment",
            index=18,
            number=20,
            type=5,
            cpp_type=1,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="user_name",
            full_name="checkin_proto.AndroidCheckinRequest.user_name",
            index=19,
            number=21,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="user_serial_number",
            full_name="checkin_proto.AndroidCheckinRequest.user_serial_number",
            index=20,
            number=22,
            type=5,
            cpp_type=1,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto2",
    extension_ranges=[],
    oneofs=[],
    serialized_start=105,
    serialized_end=564,
)


_ANDROIDCHECKINRESPONSE = _descriptor.Descriptor(
    name="AndroidCheckinResponse",
    full_name="checkin_proto.AndroidCheckinResponse",
    filename=None,
    file=DESCRIPTOR,
    containing_type=None,
    fields=[
        _descriptor.FieldDescriptor(
            name="stats_ok",
            full_name="checkin_proto.AndroidCheckinResponse.stats_ok",
            index=0,
            number=1,
            type=8,
            cpp_type=7,
            label=2,
            has_default_value=False,
            default_value=False,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="time_msec",
            full_name="checkin_proto.AndroidCheckinResponse.time_msec",
            index=1,
            number=3,
            type=3,
            cpp_type=2,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="digest",
            full_name="checkin_proto.AndroidCheckinResponse.digest",
            index=2,
            number=4,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="settings_diff",
            full_name="checkin_proto.AndroidCheckinResponse.settings_diff",
            index=3,
            number=9,
            type=8,
            cpp_type=7,
            label=1,
            has_default_value=False,
            default_value=False,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="delete_setting",
            full_name="checkin_proto.AndroidCheckinResponse.delete_setting",
            index=4,
            number=10,
            type=9,
            cpp_type=9,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="setting",
            full_name="checkin_proto.AndroidCheckinResponse.setting",
            index=5,
            number=5,
            type=11,
            cpp_type=10,
            label=3,
            has_default_value=False,
            default_value=[],
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="market_ok",
            full_name="checkin_proto.AndroidCheckinResponse.market_ok",
            index=6,
            number=6,
            type=8,
            cpp_type=7,
            label=1,
            has_default_value=False,
            default_value=False,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="android_id",
            full_name="checkin_proto.AndroidCheckinResponse.android_id",
            index=7,
            number=7,
            type=6,
            cpp_type=4,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="security_token",
            full_name="checkin_proto.AndroidCheckinResponse.security_token",
            index=8,
            number=8,
            type=6,
            cpp_type=4,
            label=1,
            has_default_value=False,
            default_value=0,
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
        _descriptor.FieldDescriptor(
            name="version_info",
            full_name="checkin_proto.AndroidCheckinResponse.version_info",
            index=9,
            number=11,
            type=9,
            cpp_type=9,
            label=1,
            has_default_value=False,
            default_value=_b("").decode("utf-8"),
            message_type=None,
            enum_type=None,
            containing_type=None,
            is_extension=False,
            extension_scope=None,
            serialized_options=None,
            file=DESCRIPTOR,
        ),
    ],
    extensions=[],
    nested_types=[],
    enum_types=[],
    serialized_options=None,
    is_extendable=False,
    syntax="proto2",
    extension_ranges=[],
    oneofs=[],
    serialized_start=567,
    serialized_end=826,
)

_ANDROIDCHECKINREQUEST.fields_by_name[
    "checkin"
].message_type = android__checkin__pb2._ANDROIDCHECKINPROTO
_ANDROIDCHECKINRESPONSE.fields_by_name["setting"].message_type = _GSERVICESSETTING
DESCRIPTOR.message_types_by_name["GservicesSetting"] = _GSERVICESSETTING
DESCRIPTOR.message_types_by_name["AndroidCheckinRequest"] = _ANDROIDCHECKINREQUEST
DESCRIPTOR.message_types_by_name["AndroidCheckinResponse"] = _ANDROIDCHECKINRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

GservicesSetting = _reflection.GeneratedProtocolMessageType(
    "GservicesSetting",
    (_message.Message,),
    dict(
        DESCRIPTOR=_GSERVICESSETTING,
        __module__="checkin_pb2"
        # @@protoc_insertion_point(class_scope:checkin_proto.GservicesSetting)
    ),
)
_sym_db.RegisterMessage(GservicesSetting)

AndroidCheckinRequest = _reflection.GeneratedProtocolMessageType(
    "AndroidCheckinRequest",
    (_message.Message,),
    dict(
        DESCRIPTOR=_ANDROIDCHECKINREQUEST,
        __module__="checkin_pb2"
        # @@protoc_insertion_point(class_scope:checkin_proto.AndroidCheckinRequest)
    ),
)
_sym_db.RegisterMessage(AndroidCheckinRequest)

AndroidCheckinResponse = _reflection.GeneratedProtocolMessageType(
    "AndroidCheckinResponse",
    (_message.Message,),
    dict(
        DESCRIPTOR=_ANDROIDCHECKINRESPONSE,
        __module__="checkin_pb2"
        # @@protoc_insertion_point(class_scope:checkin_proto.AndroidCheckinResponse)
    ),
)
_sym_db.RegisterMessage(AndroidCheckinResponse)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)