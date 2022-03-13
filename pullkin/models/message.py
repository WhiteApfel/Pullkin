from copy import deepcopy
from dataclasses import dataclass, asdict
from typing import Optional


class NotificationData:
    def __init__(self, data: dict = None):
        if not data:
            data = {}
        self.raw_data: dict = deepcopy(data)
        self.title: str = data.pop("title", None)
        self.body: str = data.pop("body", None)
        if data:
            for k, v in data.items():
                self.__setattr__(k, v)

    def __str__(self):
        return str(self.__dict__)


class Message:
    def __init__(self, data: dict = None):
        if not data:
            data = {}
        self.raw_data: dict = deepcopy(data)
        self.sender_id: Optional[str] = data.pop("from", None)
        self.priority: Optional[str] = data.pop("priority", None)
        self.notification: NotificationData = NotificationData(
            data.pop("notification", None)
        )
        self.fcmMessageId: Optional[str] = data.pop("fcmMessageId", None)
        if data:
            for k, v in data.items():
                self.__setattr__(k, v)

    def __getitem__(self, item):
        return self.raw_data[item]

    def __str__(self):
        return str(self.__dict__)


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
    gcm: AppCredentialsGcm
    fcm: AppCredentialsFcm
    keys: AppCredentialsKeys

    def __post_init__(self):
        self.gcm = AppCredentialsGcm(**self.gcm)  # type: ignore
        self.fcm = AppCredentialsFcm(**self.fcm)  # type: ignore
        self.keys = AppCredentialsKeys(**self.keys)  # type: ignore

    def __dict__(self):
        return asdict(self)

    def dict(self):
        return self.__dict__()
