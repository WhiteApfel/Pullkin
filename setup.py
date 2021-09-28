#!/bin/env python

from setuptools import find_packages, setup

push_receiver_classifiers = [
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: Implementation :: PyPy",
    "Intended Audience :: Developers",
    "Topic :: Software Development :: Libraries",
]

with open("README.md", "r") as f:
    push_receiver_readme = f.read()


def requirements():
    with open("requirements.txt", "r") as req:
        return [r for r in req.read().split("\n") if r]


setup(
    name="pullkin",
    version="0.4.1a1",
    author="Franc[e]sco & WhiteApfel",
    author_email="white@pfel.ru",
    url="https://github.com/WhiteApfel/pullkin",
    packages=find_packages("."),
    description="Like Pushkin, but subscribe to GCM/FCM and receive notifications",
    long_description=push_receiver_readme,
    long_description_content_type="text/markdown",
    license="Mozilla Public License 2.0",
    classifiers=push_receiver_classifiers,
    keywords="fcm gcm push notification receive firebase google",
    install_requires=requirements(),
    extras_require={"listen": ["http-ece"], "example": ["appdirs"]},
)
