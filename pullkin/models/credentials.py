from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator


class FirebaseInstallation(BaseModel):
    name: str
    fid: str
    refresh_token: str
    auth_token: str
    auth_token_expires_in: int


class CheckInResponse(BaseModel):
    stats_ok: bool


class AppCredentialsGcm(BaseModel):
    token: str
    app_id: str
    android_id: Annotated[str, BeforeValidator(lambda x: str(x))]  # type: ignore
    security_token: Annotated[str, BeforeValidator(lambda x: str(x))]  # type: ignore
    installation: FirebaseInstallation | None = None


class AppCredentialsFcmError(BaseModel):
    code: int
    message: str
    status: str


class AppCredentialsFcm(BaseModel):
    name: str
    token: str
    web: dict[str, str]


class AppCredentialsKeys(BaseModel):
    public: str
    private: str
    secret: str


class AppCredentials(BaseModel):
    gcm: AppCredentialsGcm
    fcm: AppCredentialsFcm | None = None
    keys: AppCredentialsKeys | None = None
