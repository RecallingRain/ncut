import json
import os
from auth.auth import encrypt_password

USERS_FILE = "users.json"

def register(username: str, password: str):
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    else:
        users = {}
    if username in users:
        print("用户已存在")
        return
    users[username] = encrypt_password(password)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)
    print(f"✅ 用户 {username} 创建成功")

if __name__ == "__main__":
    import getpass
    username = input("请输入用户名：")
    password = getpass.getpass("请输入密码（输入时隐藏）：")
    register(username, password)
