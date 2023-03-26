from dataclasses import dataclass


@dataclass
class CheckinResponse:
    is_ok: bool
    time_ms: int
    android_id: str
    security_token: str
    version_info: str
    device_data_version_info: str


@dataclass
class GcmRegisterResponse:
    token: str
