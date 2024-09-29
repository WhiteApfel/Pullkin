# Generated by the protocol buffer compiler.  DO NOT EDIT!
# sources: android_checkin.proto, checkin.proto
# plugin: python-betterproto
from dataclasses import dataclass
from typing import List

import betterproto


class DeviceType(betterproto.Enum):
    """
    enum values correspond to the type of device. Used in the
    AndroidCheckinProto and Device proto.
    """

    # Android Device
    DEVICE_ANDROID_OS = 1
    # Apple IOS device
    DEVICE_IOS_OS = 2
    # Chrome browser - Not Chrome OS.  No hardware records.
    DEVICE_CHROME_BROWSER = 3
    # Chrome OS
    DEVICE_CHROME_OS = 4


class ChromeBuildProtoPlatform(betterproto.Enum):
    PLATFORM_WIN = 1
    PLATFORM_MAC = 2
    PLATFORM_LINUX = 3
    PLATFORM_CROS = 4
    PLATFORM_IOS = 5
    PLATFORM_ANDROID = 6


class ChromeBuildProtoChannel(betterproto.Enum):
    CHANNEL_STABLE = 1
    CHANNEL_BETA = 2
    CHANNEL_DEV = 3
    CHANNEL_CANARY = 4
    CHANNEL_UNKNOWN = 5


@dataclass
class ChromeBuildProto(betterproto.Message):
    """Build characteristics unique to the Chrome browser, and Chrome OS"""

    # The platform of the device.
    platform: "ChromeBuildProtoPlatform" = betterproto.enum_field(1)
    # The Chrome instance's version.
    chrome_version: str = betterproto.string_field(2)
    # The Channel (build type) of Chrome.
    channel: "ChromeBuildProtoChannel" = betterproto.enum_field(3)


@dataclass
class AndroidCheckinProto(betterproto.Message):
    """Information sent by the device in a "checkin" request."""

    # Miliseconds since the Unix epoch of the device's last successful checkin.
    last_checkin_msec: int = betterproto.int64_field(2)
    # The current MCC+MNC of the mobile device's current cell.
    cell_operator: str = betterproto.string_field(6)
    # The MCC+MNC of the SIM card (different from operator if the device is
    # roaming, for instance).
    sim_operator: str = betterproto.string_field(7)
    # The device's current roaming state (reported starting in eclair builds).
    # Currently one of "{,not}mobile-{,not}roaming", if it is present at all.
    roaming: str = betterproto.string_field(8)
    # For devices supporting multiple user profiles (which may be supported
    # starting in jellybean), the ordinal number of the profile that is checking
    # in.  This is 0 for the primary profile (which can't be changed without
    # wiping the device), and 1,2,3,... for additional profiles (which can be
    # added and deleted freely).
    user_number: int = betterproto.int32_field(9)
    # Class of device.  Indicates the type of build proto
    # (IosBuildProto/ChromeBuildProto/AndroidBuildProto) That is included in this
    # proto
    type: "DeviceType" = betterproto.enum_field(12)
    # For devices running MCS on Chrome, build-specific characteristics of the
    # browser.  There are no hardware aspects (except for ChromeOS). This will
    # only be populated for Chrome builds/ChromeOS devices
    chrome_build: "ChromeBuildProto" = betterproto.message_field(13)


@dataclass
class GservicesSetting(betterproto.Message):
    """A concrete name/value pair sent to the device's Gservices database."""

    name: bytes = betterproto.bytes_field(1)
    value: bytes = betterproto.bytes_field(2)


@dataclass
class AndroidCheckinRequest(betterproto.Message):
    """Devices send this every few hours to tell us how they're doing."""

    # IMEI (used by GSM phones) is sent and stored as 15 decimal digits; the 15th
    # is a check digit.
    imei: str = betterproto.string_field(1)
    # MEID (used by CDMA phones) is sent and stored as 14 hexadecimal digits (no
    # check digit).
    meid: str = betterproto.string_field(10)
    # MAC address (used by non-phone devices).  12 hexadecimal digits; no
    # separators (eg "0016E6513AC2", not "00:16:E6:51:3A:C2").
    mac_addr: List[str] = betterproto.string_field(9)
    # An array parallel to mac_addr, describing the type of interface. Currently
    # accepted values: "wifi", "ethernet", "bluetooth".  If not present, "wifi"
    # is assumed.
    mac_addr_type: List[str] = betterproto.string_field(19)
    # Serial number (a manufacturer-defined unique hardware identifier).
    # Alphanumeric, case-insensitive.
    serial_number: str = betterproto.string_field(16)
    # Older CDMA networks use an ESN (8 hex digits) instead of an MEID.
    esn: str = betterproto.string_field(17)
    id: int = betterproto.int64_field(2)
    logging_id: int = betterproto.int64_field(7)
    digest: str = betterproto.string_field(3)
    locale: str = betterproto.string_field(6)
    checkin: "AndroidCheckinProto" = betterproto.message_field(4)
    # DEPRECATED, see AndroidCheckinProto.requested_group
    desired_build: str = betterproto.string_field(5)
    # Blob of data from the Market app to be passed to Market API server
    market_checkin: str = betterproto.string_field(8)
    # SID cookies of any google accounts stored on the phone.  Not logged.
    account_cookie: List[str] = betterproto.string_field(11)
    # Time zone.  Not currently logged.
    time_zone: str = betterproto.string_field(12)
    # Security token used to validate the checkin request. Required for android
    # IDs issued to Froyo+ devices, not for legacy IDs.
    security_token: float = betterproto.fixed64_field(13)
    # Version of checkin protocol. There are currently two versions: - version
    # field missing: android IDs are assigned based on   hardware identifiers.
    # unsecured in the sense that you can   "unregister" someone's phone by
    # sending a registration request   with their IMEI/MEID/MAC. - version=2:
    # android IDs are assigned randomly.  The device is   sent a security token
    # that must be included in all future   checkins for that android id. -
    # version=3: same as version 2, but the 'fragment' field is   provided, and
    # the device understands incremental updates to the   gservices table (ie,
    # only returning the keys whose values have   changed.) (version=1 was
    # skipped to avoid confusion with the "missing" version field that is
    # effectively version 1.)
    version: int = betterproto.int32_field(14)
    # OTA certs accepted by device (base-64 SHA-1 of cert files).  Not logged.
    ota_cert: List[str] = betterproto.string_field(15)
    # A single CheckinTask on the device may lead to multiple checkin requests if
    # there is too much log data to upload in a single request.  For version 3
    # and up, this field will be filled in with the number of the request,
    # starting with 0.
    fragment: int = betterproto.int32_field(20)
    # For devices supporting multiple users, the name of the current profile
    # (they all check in independently, just as if they were multiple physical
    # devices).  This may not be set, even if the device is using multiuser.
    # (checkin.user_number should be set to the ordinal of the user.)
    user_name: str = betterproto.string_field(21)
    # For devices supporting multiple user profiles, the serial number for the
    # user checking in.  Not logged.  May not be set, even if the device
    # supportes multiuser.  checkin.user_number is the ordinal of the user (0, 1,
    # 2, ...), which may be reused if users are deleted and re-created.
    # user_serial_number is never reused (unless the device is wiped).
    user_serial_number: int = betterproto.int32_field(22)


@dataclass
class AndroidCheckinResponse(betterproto.Message):
    """The response to the device."""

    stats_ok: bool = betterproto.bool_field(1)
    time_msec: int = betterproto.int64_field(3)
    # Provisioning is sent if the request included an obsolete digest. For
    # version <= 2, 'digest' contains the digest that should be sent back to the
    # server on the next checkin, and 'setting' contains the entire gservices
    # table (which replaces the entire current table on the device). for version
    # >= 3, 'digest' will be absent.  If 'settings_diff' is false, then 'setting'
    # contains the entire table, as in version 2.  If 'settings_diff' is true,
    # then 'delete_setting' contains the keys to delete, and 'setting' contains
    # only keys to be added or for which the value has changed.  All other keys
    # in the current table should be left untouched.  If 'settings_diff' is
    # absent, don't touch the existing gservices table.
    digest: str = betterproto.string_field(4)
    settings_diff: bool = betterproto.bool_field(9)
    delete_setting: List[str] = betterproto.string_field(10)
    setting: List["GservicesSetting"] = betterproto.message_field(5)
    market_ok: bool = betterproto.bool_field(6)
    android_id: str = betterproto.fixed64_field(7)
    security_token: str = betterproto.fixed64_field(8)
    version_info: str = betterproto.string_field(11)
