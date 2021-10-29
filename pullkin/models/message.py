from copy import deepcopy
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
