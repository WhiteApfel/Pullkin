# Usage Examples

This section provides examples of how to use Pullkin's core methods to register an "app" 
listen for notifications, and manage multiple "apps" simultaneously. 

## App Registration

### Simple Registration

In this example, we register an app using `Pullkin.register()` and store the returned `AppCredentials` for immediate use.

**Use Case:** This method is useful for initial testing or when you want to quickly obtain credentials 
without persistent storage.

```python
import asyncio
from pullkin import Pullkin

async def main():
    pullkin = Pullkin()
    credentials = await pullkin.register(
        sender_id="797293934120",
        app_id="1:797293934120:android:c94a6d3dcb31d27efa671d",
        api_key="AIzaSyBju9LTpHTleqT3rXTEFLlaZo0-a3oM4fA",
        firebase_project_id="pullkin",
    )
    print("App registered with credentials:", credentials)

asyncio.run(main())
```

### Registration and Saving Credentials to JSON

In this example, we register an app and save the returned `AppCredentials` as a JSON file. 
Since `AppCredentials` is a Pydantic model, we can easily serialize it to JSON.

**Use Case:** This approach is ideal for applications where the registration process needs to be performed 
only once, and credentials are reused across sessions.

```python
import asyncio
import json
from pullkin import AppCredentials, Pullkin

async def main():
    pullkin = Pullkin()
    credentials = await pullkin.register(
        sender_id="797293934120",
        app_id="1:797293934120:android:c94a6d3dcb31d27efa671d",
        api_key="AIzaSyBju9LTpHTleqT3rXTEFLlaZo0-a3oM4fA",
        firebase_project_id="pullkin",
    )

    # Save credentials to JSON file
    with open("credentials.json", "w") as file:
        file.write(credentials.model_dump_json())
    
    with open("credentials.json", "r") as file:
        credentials = AppCredentials.model_validate_json(file.read())
        
    print("App registered and credentials saved to credentials.json")

asyncio.run(main())
```

## Notification Handling

### Example 1: Listening for Notifications with a Coroutine

In this example, we create a coroutine to listen for notifications, wait for 5 seconds, 
and stop listening once a notification is received. This approach can be useful 
for short-term listening, such as testing notifications for specific cases.

**Use Case:** This approach is helpful when you need a quick listen session for debugging 
or verifying if notifications arrive within a short period.

```python
import asyncio
from pullkin import AppCredentials, Pullkin

async def main():
    pullkin = Pullkin()
    with open("credentials.json", "r") as file:
        credentials = AppCredentials.model_validate_json(file.read())
    
    await pullkin.add_app(sender_id="797293934120", credentials=credentials, persistent_ids=set())
    
    coroutine = await pullkin.listen_coroutine("797293934120")
    
    await asyncio.sleep(5)
    
    try:
        # Wait for 5 seconds to listen for notifications
        while True:
            message = await asyncio.wait_for(coroutine.asend(None), timeout=5)
            if message:
                print("Notification received:", message)
                break
    except asyncio.TimeoutError:
        print("No notification received within 5 seconds.")

asyncio.run(main())
```

### Example 2: Adding an App and Using a Decorator Handler with Coroutine Listening

Here, we add an app and set up a handler using the `on_notification()` decorator. 
We listen for notifications in a loop with a coroutine and stop the loop with `Ctrl+C`. 
This setup is useful when you want ongoing monitoring but prefer a manual exit.

**Use Case:** This approach is ideal for applications that require continuous listening 
with a structured handler but still offer manual control to terminate the listening process.

```python
import asyncio
from pullkin import AppCredentials, Pullkin, Message, DataMessageStanza

pullkin = Pullkin()
with open("credentials.json", "r") as file:
    credentials = AppCredentials.model_validate_json(file.read())

@pullkin.on_notification()
async def handle_notification(message: Message, data_message: DataMessageStanza):
    print("Notification received:", message)

async def main():
    await pullkin.add_app("797293934120", credentials=credentials, persistent_ids=set())
    coroutine = await pullkin.listen_coroutine("797293934120")

    try:
        # Continuous listening until interrupted
        while True:
            await coroutine.asend(None)
    except KeyboardInterrupt:
        print("Listening stopped by user.")

asyncio.run(main())

```

### Example 3: Running a Listener in the Background with `run()`

This example demonstrates running a background listener using the run() method 
with a handler created through a decorator. 
This approach is suitable when you want the app to handle incoming notifications 
indefinitely without manually iterating a coroutine.

**Use Case:** This setup is useful for background notification handling, especially in situations where the app 
should process notifications continuously with minimal manual interaction.

```python
import asyncio
from pullkin import AppCredentials, Pullkin, Message, DataMessageStanza

pullkin = Pullkin()
with open("credentials.json", "r") as file:
    credentials = AppCredentials.model_validate_json(file.read())

@pullkin.on_notification()
async def handle_notification(message: Message, data_message: DataMessageStanza):
    print("Notification received:", message)

async def main():
    await pullkin.add_app("797293934120", credentials=credentials, persistent_ids=set())
    await pullkin.run(timer=0.1)

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Background listener stopped by user.")

```

### Example 4: Running Multiple Apps with `run()`

In this example, we register and run two apps in the background simultaneously. This setup is valuable 
when you need to listen for notifications from multiple sources, each potentially with its own handler.

**Use Case:** This configuration is best for applications that need to handle notifications 
from different sources in parallel. It provides an efficient way to manage multiple 
notification streams with separate handlers.

```python
import asyncio
from pullkin import AppCredentials, Pullkin, Message, DataMessageStanza

pullkin = Pullkin()

with open("credentials_app1.json", "r") as file:
    app1_cred = AppCredentials.model_validate_json(file.read())
with open("credentials_app2.json", "r") as file:
    app2_cred = AppCredentials.model_validate_json(file.read())

@pullkin.on_notification(lambda m, d: m.sender_id == "SENDER_ID_1")
async def handle_notification_app1(message: Message, data_message: DataMessageStanza):
    print("App 1 notification:", message.body)

@pullkin.on_notification(lambda m, d: m.sender_id == "SENDER_ID_2")
async def handle_notification_app2(message: Message, data_message: DataMessageStanza):
    print("App 2 notification:", message.body)

async def main():
    await pullkin.add_app("SENDER_ID_1", credentials=app1_cred, persistent_ids=set())
    await pullkin.add_app("SENDER_ID_2", credentials=app2_cred, persistent_ids=set())
    await pullkin.run(timer=0.1)

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Multiple app listeners stopped by user.")
```