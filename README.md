# Pullkin

[![CodeFactor](https://www.codefactor.io/repository/github/whiteapfel/pullkin/badge/master)](https://www.codefactor.io/repository/github/whiteapfel/pullkin/overview/master)
[![Build Status](https://app.travis-ci.com/WhiteApfel/Pullkin.svg?branch=master)](https://app.travis-ci.com/WhiteApfel/Pullkin)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FWhiteApfel%2FPullkin.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FWhiteApfel%2FPullkin?ref=badge_shield)
![PyPI - Downloads](https://img.shields.io/pypi/dm/pullkin)
![GitHub](https://img.shields.io/github/license/whiteapfel/pullkin)
![GitHub last commit](https://img.shields.io/github/last-commit/whiteapfel/pullkin)

Like Pushkin, but subscribe to FCM (GCM) and receive notifications

My alternative implementation 
of [python implementation](https://github.com/Francesco149/push_receiver) 
of [JS implementation](https://github.com/MatthieuLemoine/push-receiver)

Tested on python (3.9.6, TODO: other versions)

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

```shell
pip install pullkin
```

Basic usage example that stores and loads credentials and persistent ids
and prints new notifications

You can also run this example with this command (change the sender id)

```shell
python -m pullkin --sender-id=722915550290
```
