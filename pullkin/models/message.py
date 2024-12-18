from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class NotificationData(BaseModel):
    """
    You can create a child model that describes the fields you use in the notification.

    Example:
        ```python
        class MyNotificationData(NotificationData):
            title: str
            body: str
            my_field: str
            my_another_field: dict[str, str]

        message: Message[MyNotificationData] = ...
        ```
    """

    model_config = ConfigDict(extra="allow")

    raw: dict[str, Any]

    title: str | None = None
    body: str | None = None

    @model_validator(mode="before")
    def add_raw(cls, values: dict[str, Any]) -> dict[str, Any]:
        if "raw" not in values:
            values["raw"] = dict(values)

        return values

    def __str__(self):
        return str(self.raw)


NotificationDataType = TypeVar("NotificationDataType", bound=NotificationData)
MessageType = TypeVar("MessageType")


class Message(BaseModel, Generic[NotificationDataType]):
    """
    You can create a child model that describes the fields you use in the notification.

    Example:
        ```python
        class MyMessage(Message):
            my_field: str

        class MyMessageWithGeneric(Message[MyNotificationData]):
        ```
    """

    model_config = ConfigDict(extra="allow")

    raw: dict[str, Any]

    data: dict[str, Any] | None = None
    sender_id: str | None = Field(None, alias="from")
    priority: str | None = None
    notification: NotificationDataType | None = None
    fcm_message_id: str | None = Field(None, alias="fcmMessageId")

    @model_validator(mode="before")
    def add_raw(cls, values: dict[str, Any]) -> dict[str, Any]:
        if "raw" not in values:
            values["raw"] = dict(values)

        return values

    def to_another_model(self, another_model: MessageType) -> MessageType:
        """
        You can use this method to convert a Message-model to your model.
        A Message will be converted into the another_model using `another_model.model_validate(self.raw)`

        If you use a handler with type hinting, the message model will be converted automatically.

        Example: Example: Manually convert
            ```python
            message: Message = ...

            my_message: Message[MyNotificationData] = message.to_another_model(Message[MyNotificationData])
            my_message: MyMessage[MyNotificationData] = message.to_another_model(MyMessage[MyNotificationData])
            my_message: MyMessage[NotificationData] = message.to_another_model(MyMessage[NotificationData])
            my_message: MyMessage = message.to_another_model(MyMessage)

            # or use simple
            my_message: MyMessage[MyNotificationData] = MyMessage[MyNotificationData].model_validate(message.raw)
            ```

        Example: Example: Auto convert with handler-style
            ```python
            @pullkin.on_notification()
            async def on_notification(notification: MyMessage[MyNotificationData], data_message: DataMessageStanza):
                print(notification)
            ```
        """
        generic_metadata = getattr(another_model, "__pydantic_generic_metadata__", None)

        if generic_metadata:
            message_model = generic_metadata.get("origin") or Message
            notification_model = (generic_metadata.get("args") or (None,))[0]

            if notification_model:
                return message_model[notification_model].model_validate(self.raw)

        # If no generic arguments, validate the raw data with the provided model
        return another_model.model_validate(self.raw)

    def __getitem__(self, item):
        return self.raw[item]

    def __str__(self):
        return str(self.raw)
