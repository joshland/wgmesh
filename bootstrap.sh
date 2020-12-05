#!/bin/bash

[ -e Python ] || python3 -m venv Python
source Python/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

