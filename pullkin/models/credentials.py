from dataclasses import asdict, dataclass
from typing import Union


@dataclass
class FirebaseInstallationResponse:
    name: str
    fid: str
    refresh_token: str
    auth_token: str
    auth_token_expires_in: int


@dataclass
class CheckInResponse:
    stats_ok: bool


@dataclass
class AppCredentialsGcm:
    token: str
    app_id: str
    android_id: str
    security_token: str
    installation: FirebaseInstallationResponse

    def __post_init__(self):
        if isinstance(self.android_id, int):
            self.android_id = str(self.android_id)

        if isinstance(self.security_token, int):
            self.security_token = str(self.security_token)


@dataclass
class AppCredentialsFcm:
    token: str
    pushSet: str


@dataclass
class AppCredentialsKeys:
    public: str
    private: str
    secret: str


@dataclass
class AppCredentials:
    gcm: Union[AppCredentialsGcm, dict]
    fcm: Union[AppCredentialsFcm, dict]
    keys: Union[AppCredentialsKeys, dict]

    def __post_init__(self):
        if isinstance(self.gcm, dict):
            self.gcm: AppCredentialsGcm = AppCredentialsGcm(**self.gcm)  # type: ignore
        if isinstance(self.fcm, dict):
            self.fcm: AppCredentialsFcm = AppCredentialsFcm(**self.fcm)  # type: ignore
        if isinstance(self.keys, dict):
            self.keys: AppCredentialsKeys = AppCredentialsKeys(**self.keys)  # type: ignore

    def __dict__(self):
        return asdict(self)

    def dict(self):
        return self.__dict__()
