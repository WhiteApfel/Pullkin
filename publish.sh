#!/bin/sh

rm -rf dist/
rm -rf build/
python setup.py clean sdist bdist_wheel --universal
twine upload dist/*
