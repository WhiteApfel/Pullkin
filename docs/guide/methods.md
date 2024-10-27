# Core Methods

Pullkin provides key methods for registering an "app" in the Firebase Cloud Messaging (FCM) infrastructure 
and for handling received notifications. These methods fall into two main categories:

1. **Registration and Setup Methods** — used to register a device or "app" for receiving notifications.
2. **Notification Handling Methods** — used to retrieve and manage incoming notifications.

## Registration and Setup Methods

### `register()`

The `Pullkin.register()` method registers with GCM and FCM and returns an `AppCredentials` 
object containing credentials needed for subscribing and receiving notifications.

#### Signature Code

```python
async def register(
    sender_id: str | int,
    app_id: str,
    api_key: str,
    firebase_project_id: str,
    android_cert: str = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    app_name: str = "org.chromium.linux",
    retries: int = 5,
) -> AppCredentials:
    ...
```

#### Usage Example

```python
cred = await pullkin.register(
    "797293934120",
    "1:797293934120:android:c94a6d3dcb31d27efa671d",
    "AIzaSyBju9LTpHTleqT3rXTEFLlaZo0-a3oM4fA",
    "pullkin",
)
```

## Notification Handling Methods

### `add_app()`

The `add_app()` method subscribes a device to a specific app.

#### Signature Code

```python
async def add_app(
    self, 
    sender_id: str, 
    credentials: AppCredentials, 
    persistent_ids: set[str]
) -> None:
    ...
```

#### Usage Example

```python
await client.add_app(SENDER_ID, fcm_cred, set())
```

### `on_notification()`

The `on_notification()` decorator allows you to add a handler for notifications that meet specific filter criteria.

#### Signature Code

```python
def on_notification(
    self,
    handler_filter: Callable[
        [Message, DataMessageStanza], None
    ] = lambda *a, **k: True,
) -> [Message, DataMessageStanza], Optional[Awaitable]:
    ...
```

#### Usage Example

```python
@pullkin.on_notification(lambda m, d: m.sender_id == "123456789")
async def on_specific_sender(notification: Message, data_message: DataMessageStanza):
    print(notification)
```

### `listen_coroutine()`

The `listen_coroutine()` method creates a coroutine to receive notifications. 
Each coroutine iteration corresponds to a received notification.

#### Signature Code

```python
async def listen_coroutine(
    self,
    sender_id: int | str | None = None,
) -> AsyncGenerator[Message | None, None]:
    ...
```

#### Usage Example

```python
coroutine = await client.listen_coroutine("123456789")
while not (message := await coroutine.asend(None)):
    await asyncio.sleep(0.5)
    print(message)
```

### `run()`

The `run()` method launches a background task that continuously listens for notifications and processes them.

#### Signature Code

```python
async def run(
    self,
    sender_ids: list[str] | None = None,
    timer: Union[int, float] = 0.05,
) -> None:
    ...
```

#### Usage Example

```python
await client.run(timer=0.1)
```

For practical usage examples of these methods, 
please refer to the [Usage Examples](/guide/examples) section, 
where you can find sample code demonstrating how to implement each method effectively.