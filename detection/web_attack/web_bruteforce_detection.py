# web_bruteforce_detection.py
"""
Web Attack – Brute Force Detection Module
检测 Web 登录暴力破解（大量连续失败登录）

接口:
    detect_web_bruteforce(http_record: dict) -> tuple

返回:
    (is_attack, src_ip, attack_type)
    is_attack 可为 True / False / "suspected"
    非攻击时返回 (False, None, None)

配置项:
    fail_threshold           短窗连续失败阈值
    window_seconds           短窗长度
    long_window_seconds      长窗长度（检测慢速爆破）
    long_fail_threshold      长窗连续失败阈值
    login_paths             监控登录 URI 关键字列表
    fail_status              失败 HTTP 状态码列表
    success_status           成功状态码列表
"""
# NOTE: 本模块只应处理 HTTP 记录。当 detection_manager 误将非 HTTP
#       流量转过来时，任何字段都可能缺失；因此下面的 detect_web_bruteforce
#       必须先全面判空再做判断，避免 AttributeError / KeyError。
import time
from collections import defaultdict, deque
from threading import RLock
from typing import Deque, Dict, Tuple, Union
from collections import Counter

# ---------------- 全局状态 ---------------- #
# 失败计数窗口：{key: deque[timestamps]}
_fail_windows: Dict[str, Deque[float]] = defaultdict(deque)
# 慢速计数窗口
_long_fail_windows: Dict[str, Deque[float]] = defaultdict(deque)
# 全局可重入锁，兼容多线程或 async 落地的线程池执行器
_lock = RLock()

# ---------------- 配置 ---------------- #
# 所有值在 init_config() 时从 YAML 注入，可覆盖默认
FAIL_THRESHOLD = 15           # 短窗连续失败阈值
WINDOW_SECONDS = 120          # 短窗长度
LONG_WINDOW_SECONDS = 900     # 长窗长度（检测慢速爆破）
LONG_FAIL_THRESHOLD = 50      # 长窗连续失败阈值
LOGIN_PATHS = ["/login"]      # 监控登录 URI 关键字
FAIL_STATUS = [401, 403, 429] # 失败 HTTP 状态码
SUCCESS_STATUS = [200, 302]   # 成功状态码

def init_config(config: dict) -> None:
    """
    在 detection_manager 启动时调用，注入 web.brute_force 配置
    """
    global FAIL_THRESHOLD, WINDOW_SECONDS, LONG_WINDOW_SECONDS, LONG_FAIL_THRESHOLD, LOGIN_PATHS, FAIL_STATUS, SUCCESS_STATUS
    web_cfg = config.get("web", {}).get("brute_force", {})
    FAIL_THRESHOLD = int(web_cfg.get("fail_threshold", FAIL_THRESHOLD))
    WINDOW_SECONDS = int(web_cfg.get("window_seconds", WINDOW_SECONDS))
    LONG_WINDOW_SECONDS = int(web_cfg.get("long_window_seconds", LONG_WINDOW_SECONDS))
    LONG_FAIL_THRESHOLD = int(web_cfg.get("long_fail_threshold", LONG_FAIL_THRESHOLD))
    LOGIN_PATHS = web_cfg.get("login_paths", LOGIN_PATHS)
    FAIL_STATUS = web_cfg.get("fail_status", FAIL_STATUS)
    SUCCESS_STATUS = web_cfg.get("success_status", SUCCESS_STATUS)


# ---------------- 工具函数 ---------------- #
def _clean_expired(q: Deque[float], now_ts: float, window: int = WINDOW_SECONDS) -> None:
    """移除过期时间戳"""
    expiry = now_ts - window
    while q and q[0] <= expiry:
        q.popleft()


def _record_failure(key: str, now_ts: float) -> int:
    """记录一次失败，返回当前窗口内的失败计数"""
    with _lock:
        q = _fail_windows[key]
        _clean_expired(q, now_ts)
        q.append(now_ts)
        # 长窗
        q_long = _long_fail_windows[key]
        _clean_expired(q_long, now_ts, LONG_WINDOW_SECONDS)
        q_long.append(now_ts)
        return len(q)


def _reset_key(key: str) -> None:
    """登录成功 —— 清零对应窗口"""
    with _lock:
        if key in _fail_windows:
            _fail_windows.pop(key, None)
        if key in _long_fail_windows:
            _long_fail_windows.pop(key, None)


# ---------------- 主检测函数 ---------------- #
def detect_web_bruteforce(
    http_record: dict
) -> tuple[bool, None, None] | tuple[bool, dict[str, str], str] | tuple[str, dict[str, str], str]:
    """
    侦测 Web 登录暴力破解

    参数:
        http_record: 捕获模块解析出的 HTTP 记录
            字段要求:
              - src_ip (str)
              - method (str)
              - url (str)
              - status (int)  # HTTP 响应码，必填
              - body (str)    # POST 表单原始串，可为空
    返回:
        (is_attack, src_ip, attack_type)
        is_attack 可为 True / False / "suspected"
        非攻击时返回 (False, None, None)
    """
    # -------- 防御式编程：确保传入对象及关键字段存在 --------
    if not http_record or not isinstance(http_record, dict):
        return False, None, None

    now_ts: float = http_record.get("timestamp", time.time())
    src_ip: str = http_record.get("src_ip", "")
    status: int = http_record.get("http_status", http_record.get("status", 0))
    try:
        status = int(status)
    except Exception:
        # status 字段缺失或非整数 → 忽略
        return False, None, None
    _method = http_record.get("method", "")

    url = (http_record.get("url") or "").lower()
    if not url:
        # 无 URL 说明不是 HTTP 请求，直接忽略
        return False, None, None
    if not any(p.lower() in url for p in LOGIN_PATHS):
        return False, None, None

    # ---------- 根据响应码判定成功 / 失败 ----------
    is_fail = status in FAIL_STATUS
    is_success = status in SUCCESS_STATUS

    # Key 1: IP，Key 2: Username (若能解析到)
    username = _extract_username(http_record.get("body", ""))
    keys = [f"IP:{src_ip}"]
    if username:
        keys.append(f"USER:{username}")

    # ---------- 成功则重置计数 ----------
    if is_success:
        for k in keys:
            _reset_key(k)
        return False, None, None

    # ---------- 失败则计数 ----------
    if is_fail:
        max_count = 0
        max_long = 0
        for k in keys:
            cnt = _record_failure(k, now_ts)
            max_count = max(max_count, cnt)
            long_cnt = len(_long_fail_windows[k])
            max_long = max(max_long, long_cnt)

        if max_count >= FAIL_THRESHOLD:
            return True, {"src": src_ip}, "Web Bruteforce"
        elif max_count >= int(0.8 * FAIL_THRESHOLD):
            return "suspected", {"src": src_ip}, "Web Bruteforce"
        if max_long >= LONG_FAIL_THRESHOLD:
            return True, {"src": src_ip}, "Web Bruteforce Slow"

    # 如果既不成功也不失败（奇怪的状态码），直接返回非攻击
    # 默认非攻击
    return False, None, None


# ---------------- 辅助解析 ---------------- #
def _extract_username(body: str) -> str:
    """
    简易提取 username 字段（application/x-www-form-urlencoded）
    若项目在 JSON/多表单等场景，可自行扩展
    """
    if not body or "=" not in body:
        return ""
    for kv in body.split("&"):
        if kv.lower().startswith("username="):
            return kv.split("=", 1)[1]
    return ""