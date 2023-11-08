from typing import Annotated

from pydantic import BaseModel, BeforeValidator


class FirebaseInstallationResponse(BaseModel):
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
    android_id: Annotated[str, BeforeValidator(lambda x: str(x))]
    security_token: Annotated[str, BeforeValidator(lambda x: str(x))]
    installation: FirebaseInstallationResponse


class AppCredentialsFcm(BaseModel):
    token: str
    pushSet: str


class AppCredentialsKeys(BaseModel):
    public: str
    private: str
    secret: str


class AppCredentials(BaseModel):
    gcm: AppCredentialsGcm
    fcm: AppCredentialsFcm
    keys: AppCredentialsKeys
