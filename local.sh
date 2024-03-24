#!/bin/bash

function fail(){
    echo "FAILED: $*"
    exit
}

#
# Ansible bootstrapper
#
if [ -e Python/ ]; then
    echo "Purge old env"
    rm -fR Python/
fi

if [ -e activate ]; then
    echo "Remove old shortcut"
    rm activate
fi

echo 'Build Virtual Env'
python3 -m venv Python > local.log || fail "Virtual Environment build failed"
source Python/bin/activate
pip install --upgrade pip wheel >> local.log || fail "Failed to Update PIP and Wheel."
pip install --upgrade -r requirements.txt >> local.log || fail "Failed to Install requirements."

ln -s Python/bin/activate activate > /dev/null

echo ''
echo "Probably complete"
echo 'to enter the env: `source Python/bin/activate`'
echo '-or-'
echo 'use the shortcut: `source activate`'

