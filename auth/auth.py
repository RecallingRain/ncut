# auth.py：密码加密与验证模块
# 提供基于 HMAC-SHA256 的密码加密和验证功能
import hmac
import hashlib
import base64

# 导入所需库：hmac 用于生成消息认证码，hashlib 提供 SHA256 算法，base64 用于编码输出

# 本地密钥：用于 HMAC-SHA256 加密的秘钥
SECRET = "local-secret-key"

# encrypt_password：对明文密码进行 HMAC-SHA256 加密，并返回 URL 安全的 Base64 字符串
def encrypt_password(password: str) -> str:
    # 生成 HMAC-SHA256 摘要，并进行 URL 安全的 Base64 编码
    return base64.urlsafe_b64encode(
        hmac.new(SECRET.encode(), password.encode(), hashlib.sha256).digest()
    ).decode()

# verify_password：验证输入密码与存储的哈希值是否一致，返回 True 表示匹配
def verify_password(input_password: str, stored_hash: str) -> bool:
    # 对输入密码进行同样的加密，并与存储哈希进行比较
    return encrypt_password(input_password) == stored_hash
