from pydantic import BaseModel


class CheckinResponse(BaseModel):
    is_ok: bool
    time_ms: int
    android_id: str
    security_token: str
    version_info: str
    device_data_version_info: str


class GcmRegisterResponse(BaseModel):
    token: str
