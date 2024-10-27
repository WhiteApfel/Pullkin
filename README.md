# Pullkin

[![CodeFactor](https://www.codefactor.io/repository/github/whiteapfel/pullkin/badge/master)](https://www.codefactor.io/repository/github/whiteapfel/pullkin/overview/master)
[![Build Status](https://app.travis-ci.com/WhiteApfel/Pullkin.svg?branch=master)](https://app.travis-ci.com/WhiteApfel/Pullkin)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pullkin)
![GitHub](https://img.shields.io/github/license/whiteapfel/pullkin)
![GitHub last commit](https://img.shields.io/github/last-commit/whiteapfel/pullkin)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pullkin)

Like Alexander Pushkin, but subscribe to FCM (GCM) and receive notifications

An alternative asynchronous implementation in Python 
of [Francesco's Python implementation](https://github.com/Francesco149/push_receiver) 
and [Matthieu Lemoine's JavaScript implementation](https://github.com/MatthieuLemoine/push-receiver).

Tested on Python 3.12 (I'm sorry, but I'm too exhausted to test it on 3.10, 3.11 and PyPy)

This library is not a wrapper, but a complete redesign of the Push Receiver by Franc[e]sco. 
Although the core logic of the original implementation is reused,
this project takes a different approach to the structure and design of the library.

## Differences

* Implemented asynchronous listener
* Implemented asynchronous coroutine-based listener
* Added support for multiple apps
* Utilized pydantic models for data representation
* Replaced functions with a listener class

## Docs

For more information, please visit the [docs on Read the Docs](https://pullkin.readthedocs.io/en/latest/).
The documentation contains more detailed information about usage, 
examples of how to use Pullkin for different scenarios, 
and provides a more comprehensive overview of the library.

## Usage

### Installation

```shell
pip install pullkin
```

### How to use
This example shows how to use the Pullkin library to receive push notifications.

Note: in real-world applications, you should use a secure way to store your credentials.

```python
import json
import os.path
import asyncio

from pullkin import Pullkin
from pullkin.models import Message, AppCredentials
from pullkin.proto.mcs_proto import DataMessageStanza

# Replace it with your actual values
SENDER_ID = '<<SENDER_ID>>'  # '1234567890'
# ANOTHER_SENDER_ID = '<<SENDER_ID>>'  # '1234567890'
APP_ID = '<<APP_ID>>'  # '1:1234567890:android:abcdef1234567890'
API_ID = '<<API_ID>>'  # 'AIzaSyDce4zFw4CqLqW2eCOqTbXfDx9a8mRnLpI'
FIREBASE_NAME = '<<FIREBASE_NAME>>'  # 'pullkin-example'
ANDROID_CERT = '<<ANDROID_CERT>>'  # 'da39a3ee5e6b4b0d3255bfef95601890afd80709' - default
APP_NAME = '<<APP_NAME>>'  # 'cc.pullkin.example' - default

pullkin = Pullkin()

# See https://pullkin.readthedocs.io/en/latest/API/modules/#pullkin.core.PullkinCore.register for more information
async def register_app(sender_id: str, app_id: str, api_id: str, firebase_name: str, android_cert: str, app_name: str):
    """
    Registers an app with Pullkin.

    :param sender_id: The sender ID of your app. Can be found in the Firebase
        console, in the "Cloud Messaging" section.
    :param app_id: The ID of your app. Can be found in the Firebase console,
        in the "General" section.
    :param api_id: The API key of your app. Can be found in the Google Cloud
        console, in the "APIs & Services" > "Dashboard" section.
    :param firebase_name: The name of your Firebase project. Can be found in the
        Firebase console, in the "General" section.
    :param android_cert: The SHA-1 hash of your app's certificate. Can be found
        in the Google Play console, in the "Release management" > "App signing"
        section.
    :param app_name: The name of your app. Can be found in the Google Play console,
        in the "Store listing" section.
    :return: The credentials of the registered app
    """
    if not os.path.exists('.pullkin_app_credentials'):
        with open('.pullkin_app_credentials', 'w+') as f:
            credentials = await pullkin.register(sender_id, app_id, api_id, firebase_name, android_cert, app_name)
            f.write(json.dumps(credentials.model_dump(mode="json")))
    else:
        with open('.pullkin_app_credentials', 'r') as f:
            credentials = AppCredentials.model_validate(json.loads(f.read()))
    return credentials


@pullkin.on_notification()
async def on_notification(notification: Message, data_message: DataMessageStanza):
    print(notification, data_message)


async def main():
    # Register the app and get the credentials
    credentials = await register_app(SENDER_ID, APP_ID, API_ID, FIREBASE_NAME, ANDROID_CERT, APP_NAME)

    # See https://pullkin.readthedocs.io/en/latest/#adding-an-app for more information
    await pullkin.add_app(sender_id=SENDER_ID, credentials=credentials)

    # Add another app if it is necessary
    # credentials = await register_app(ANOTHER_SENDER_ID, ANOTHER_APP_ID, ANOTHER_API_ID, ANOTHER_FIREBASE_NAME, ANOTHER_ANDROID_CERT, ANOTHER_APP_NAME)
    # await pullkin.add_app(sender_id=ANOTHER_SENDER_ID, credentials=credentials)

    # See https://pullkin.readthedocs.io/en/latest/API/modules/#pullkin.Pullkin.run for more information
    await pullkin.run()


asyncio.run(main())
```