# Pullkin

Like Pushkin, but subscribe to FCM (GCM) and receive notifications

My alternative implementation 
of [python implementation](https://github.com/Francesco149/push_receiver) 
of [JS implementation](https://github.com/MatthieuLemoine/push-receiver)

Tested on python (3.9.6, TODO: other versions)

I almost didn't write anything to consider it my intellectual property, 
just wrapped the code already written by Franc[e]sco in a design convenient for my own use 

Note that for the listening part Franc[e]sco has to pull in http-ece which depends
on a full blown native crypto library rather than just oscrypto. it is
an optional dependency so you'll have to install it explicitly by depending
on pullkin[listen]

## Usage

```shell
pip install pullkin
```

basic usage example that stores and loads credentials and persistent ids
and prints new notifications

you can also run this example with this command (change the sender id)


```shell
python -m pullkin --sender-id=722915550290
```

```python
from pullkin import register, listen
import json


def on_notification(obj, notification, data_message):
  idstr = data_message.persistent_id + "\n"

  # check if we already received the notification
  with open("persistent_ids.txt", "r") as f:
    if idstr in f:
      return

  # new notification, store id so we don't read it again
  with open("persistent_ids.txt", "a") as f:
    f.write(idstr)

  # print notification
  n = notification["notification"]
  text = n["title"]
  if n["body"]:
    text += ": " + n["body"]
  print(text)


if __name__ == "__main__":
  SENDER_ID = 722915550290  # change this to your sender id

  try:
    # already registered, load previous credentials
    with open("credentials.json", "r") as f:
      credentials = json.load(f)

  except FileNotFoundError:
    # first time, register and store credentials
    credentials = register(sender_id=SENDER_ID)
    with open("credentials.json", "w") as f:
      json.dump(credentials, f)

  print("send notifications to {}".format(credentials["fcm"]["token"]))

  with open("persistent_ids.txt", "a+") as f:
    received_persistent_ids = [x.strip() for x in f]

  listen(credentials, on_notification, received_persistent_ids)
```