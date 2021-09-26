#!/bin/env python

from setuptools import setup, find_packages

push_receiver_classifiers = [
    "Programming Language :: Python :: 3",
    "Intended Audience :: Developers",
    "Topic :: Software Development :: Libraries"
]

with open("README.md", "r") as f:
    push_receiver_readme = f.read()

setup(
    name="pullkin",
    version="0.3.1a2",
    author="Franc[e]sco & WhiteApfel",
    author_email="white@pfel.ru",
    url="https://github.com/WhiteApfel/Pullkin",
    packages=find_packages("."),
    description="Like Pushkin, but he subscribe to GCM/FCM and receive notifications",
    long_description=push_receiver_readme,
    long_description_content_type="text/markdown",
    license="Unlicense",
    classifiers=push_receiver_classifiers,
    keywords="fcm gcm push notification firebase google",
    install_requires=["oscrypto", "protobuf"],
    extras_require={
        "listen": ["http-ece"],
        "example": ["appdirs"]
    }
)
