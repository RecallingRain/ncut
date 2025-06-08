#!/bin/bash

# 手动设置你的sudo密码
PASSWORD=WlbqczkBndbddt020815@

# 激活虚拟环境
source /Users/recallingrain/Project-Code/PycharmProjects/system/.venv/bin/activate

# 用echo把密码输入到sudo
echo "$PASSWORD" | sudo -S /Users/recallingrain/Project-Code/PycharmProjects/system/.venv/bin/python /Users/recallingrain/Project-Code/PycharmProjects/system/capture/capture.py
