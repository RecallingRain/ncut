#!/bin/bash

PASSWORD=WlbqczkBndbddt020815@

source /Users/recallingrain/Project-Code/PycharmProjects/System/.venv/bin/activate

echo "$PASSWORD" | sudo -S -v

sudo uvicorn main:app --reload --port 8000

