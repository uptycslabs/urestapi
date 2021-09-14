#!/bin/bash
rm -rf ./urestapi.egg-info ./dist ./build
python setup.py bdist_wheel
python -m twine upload dist/*
rm -rf ./urestapi.egg-info ./dist ./build

