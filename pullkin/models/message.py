from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class NotificationData(BaseModel):
    """
    You can create a child model that describes the fields you use in the notification.

    Example:
        class MyNotificationData(NotificationData):
            title: str
            body: str
            my_field: str
            my_another_field: dict[str, str]

        message: Message[MyNotificationData] = ...
    """

    model_config = ConfigDict(extra="allow")

    raw: dict[str, Any]

    title: str | None = None
    body: str | None = None

    @model_validator(mode="before")
    def add_raw(cls, values: dict[str, Any]) -> dict[str, Any]:
        values["raw"] = values

        return values

    def __str__(self):
        return str(self.raw)


NotificationDataType = TypeVar("NotificationDataType", bound=NotificationData)
MessageType = TypeVar("MessageType")


class Message(BaseModel, Generic[NotificationDataType]):
    """
    You can create a child model that describes the fields you use in the notification.

    Example:
        class MyMessage(Message):
            my_field: str

        class MyMessageWithGeneric(Message[MyNotificationData]):

    """

    model_config = ConfigDict(extra="allow")

    raw: dict[str, Any]

    sender_id: str | None = None
    priority: str | None = None
    notification: NotificationDataType
    fcm_message_id: str | None = Field(None, alias="fcmMessageId")

    @model_validator(mode="before")
    def add_raw(cls, values: dict[str, Any]) -> dict[str, Any]:
        values["raw"] = values

        return values

    def to_another_model(self, another_model: MessageType) -> MessageType:
        """
        You can use this method to convert model to your model.
        A message will be converted into the another_model using another_model.model_validate(self.raw)

        message: Message = ...

        my_message: Message[MyNotificationData] = message.to_another_model(Message[MyNotificationData])
        my_message: MyMessage[MyNotificationData] = message.to_another_model(MyMessage[MyNotificationData])
        my_message: MyMessage[NotificationData] = message.to_another_model(MyMessage[NotificationData])
        my_message: MyMessage = message.to_another_model(MyMessage)
        # or use simple
        my_message: MyMessage[MyNotificationData] = MyMessage[MyNotificationData].model_validate(message.raw)
        """
        generic_metadata = another_model.__pydantic_generic_metadata__

        MessageModel = generic_metadata.get("origin") or Message
        (NotificationModel,) = generic_metadata.get("args") or (None,)

        if NotificationModel:
            return MessageModel[NotificationModel].model_validate(self.raw)

        return MessageModel.model_validate(self.raw)

    def __getitem__(self, item):
        return self.raw[item]

    def __str__(self):
        return str(self.raw)
