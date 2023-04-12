# Pullkin

[![CodeFactor](https://www.codefactor.io/repository/github/whiteapfel/pullkin/badge/master)](https://www.codefactor.io/repository/github/whiteapfel/pullkin/overview/master)
[![Build Status](https://app.travis-ci.com/WhiteApfel/Pullkin.svg?branch=master)](https://app.travis-ci.com/WhiteApfel/Pullkin)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pullkin)
![GitHub](https://img.shields.io/github/license/whiteapfel/pullkin)
![GitHub last commit](https://img.shields.io/github/last-commit/whiteapfel/pullkin)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pullkin)

Like Pushkin, but subscribe to FCM (GCM) and receive notifications

My alternative implementation 
of [python implementation](https://github.com/Francesco149/push_receiver) 
of [JS implementation](https://github.com/MatthieuLemoine/push-receiver)

Tested on python (3.6, 3.8, 3.10, pypy3.7-7.3.5)

I almost didn't write anything to consider it my intellectual property, 
just wrapped the code already written by Franc[e]sco in a design convenient for my own use 

Note that for the listening part Franc[e]sco has to pull in http-ece which depends
on a full-blown native crypto library rather than just oscrypto. it is
an optional dependency, so you'll have to install it explicitly by depending
on `pullkin[listen]`

## Differences

* Add async listener
* Add async listener-coroutine
* Replace functions with class of listener

## Usage

### Installation

```shell
pip install pullkin
```

### How to use

```python
import json
import os.path
import asyncio

from pullkin import Pullkin
from pullkin.models import Message, AppCredentials

SENDER_ID = '<<SENDER_ID>>'  # '1234567890'
APP_ID = '<<APP_ID>>'  # '1:1234567890:android:abcdef1234567890'
API_ID = '<<API_ID>>'  # 'AIzaSyDce4zFw4CqLqW2eCOqTbXfDx9a8mRnLpI'
FIREBASE_NAME = '<<FIREBASE_NAME'  # 'pullkin-example'
APP_NAME = '<<APP_NAME>>'  # 'cc.pullkin.example'

#
ANDROID_CERT = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'  
# 'da39a3ee5e6b4b0d3255bfef95601890afd80709' is default hash

pullkin = Pullkin()

if not os.path.exists('.persistent_ids.txt'):
    with open('.persistent_ids.txt', 'w+') as f:
        ...

with open(".persistent_ids.txt", "r") as f:
    received_persistent_ids = [x.strip() for x in f]


@pullkin.on_notification()
async def on_notification(message: Message, data_message):
    idstr = data_message.persistent_id + "\n"
    with open(".persistent_ids.txt", "r") as f:
        if idstr in f:
            return
    with open(".persistent_ids.txt", "a") as f:
        f.write(idstr)
    print(message.notification)


async def main():
    if not os.path.exists('.pullkin_app_credentials'):
        with open('.pullkin_app_credentials', 'w+') as f:
            credentials = await pullkin.register(SENDER_ID, APP_ID, API_ID, FIREBASE_NAME, ANDROID_CERT,  APP_NAME)
            f.write(json.dumps(credentials.dict()))
    else:
        with open('.pullkin_app_credentials', 'r') as f:
            credentials = AppCredentials(**json.loads(f.read()))
    await pullkin.run(
        sender_id=SENDER_ID,
        credentials=credentials,
        persistent_ids=received_persistent_ids,
    )


asyncio.run(main())
```