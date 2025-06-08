#!/bin/bash

# 手动设置你的sudo密码
PASSWORD=WlbqczkBndbddt020815@

# 激活虚拟环境
source /Users/recallingrain/Project-Code/PycharmProjects/system/.venv/bin/activate

# ① 喂密码给 sudo，更新/验证凭证缓存，后续一段时间内不用再输密码
echo "$PASSWORD" | sudo -S -v

# ② 用缓存好的 sudo 直接跑 main.py，stdin 仍然是你的终端，所有的 input() 交互都保留
sudo /Users/recallingrain/Project-Code/PycharmProjects/system/.venv/bin/python /Users/recallingrain/Project-Code/PycharmProjects/system/main.py