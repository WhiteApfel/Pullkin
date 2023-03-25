from dataclasses import asdict, dataclass
from typing import Union


@dataclass
class AppCredentialsGcm:
    token: str
    appId: str
    androidId: str
    securityToken: str


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
        self.gcm: AppCredentialsGcm = AppCredentialsGcm(**self.gcm)  # type: ignore
        self.fcm: AppCredentialsFcm = AppCredentialsFcm(**self.fcm)  # type: ignore
        self.keys: AppCredentialsKeys = AppCredentialsKeys(**self.keys)  # type: ignore

    def __dict__(self):
        return asdict(self)

    def dict(self):
        return self.__dict__()
