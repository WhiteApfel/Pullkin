# Installation Guide

Pullkin supports Python versions 3.10 through 3.13 
due to the use of new syntax features, such as `str | bytes`.

To install the Pullkin library, you have several options depending on your setup and requirements. 
Below are instructions for installation via PyPI, SSH, and direct repository cloning.

## Installation via PyPI

The easiest way to install Pullkin is from the Python Package Index (PyPI) using `pip`:

```bash
pyhton -m pip install pullkin
```

This will install the latest stable version of Pullkin from PyPI.

## Installation via SSH

If you prefer to install directly from the GitHub repository over SSH, use the following command:

```bash
python -m pip install git+https://github.com/whiteapfel/pullkin.git
```

Ensure you have set up SSH access to GitHub before using this command.

## Installation via Repository Cloning

Alternatively, you can clone the repository and install the library manually:

```bash
git clone https://github.com/whiteapfel/pullkin.git
cd pullkin
pip install .
```

This approach is useful if you want to work with the latest changes or modify the code locally.
