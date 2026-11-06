#!/bin/zsh
cd "$(dirname "$0")"
export AWS_PROFILE=scanner
.venv/bin/python local_app.py
