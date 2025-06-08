# 文件: bruteforce_detection.py

from collections import deque, defaultdict
from typing import Any
import logging

logger = logging.getLogger(__name__)

# —— 配置参数 ——
CONFIG = {
"WINDOW_SIZE" : 60,     # 滑动窗口长度（秒）
"SMOOTH_ALPHA" : 0.3,   # 指数平滑系数
"THRESHOLD_MULTIPLIER" : 4, # 阈值倍率（平滑值 * multiplier）
"FTP_MIN_THRESHOLD": 5,    # FTP爆破下限
"SSH_MIN_THRESHOLD": 3     # SSH爆破下限
}

# —— 全局状态 ——
# 存储 {ip: deque([timestamps])}
_fail_times = defaultdict(deque)
# 存储 {ip: float} 平滑后的失败率估计
_smooth_rate = defaultdict(lambda: 0.0)

def clear_state():
    """清空全局状态，供测试隔离使用"""
    _fail_times.clear()
    _smooth_rate.clear()

def load_config(cfg: dict) -> None:
    """
    从传入的 cfg 字典更新模块参数。
    """
    if not isinstance(cfg, dict):
        return
    CONFIG.update(cfg)



def _record_failure(ip: str, timestamp: float):
    """记录一次失败，并清理过期记录"""
    dq = _fail_times[ip]
    dq.append(timestamp)
    # 移除窗口外的记录
    WINDOW_SIZE = CONFIG['WINDOW_SIZE']
    while dq and dq[0] < timestamp - WINDOW_SIZE:
        dq.popleft()

def _update_smooth(ip: str, count: int):
    """用指数平滑更新失败率估计"""
    prev = _smooth_rate[ip]
    WINDOW_SIZE = CONFIG['WINDOW_SIZE']
    rate = count / WINDOW_SIZE
    SMOOTH_ALPHA = CONFIG['SMOOTH_ALPHA']
    _smooth_rate[ip] = SMOOTH_ALPHA * rate + (1 - SMOOTH_ALPHA) * prev

def detect_ftp_patator(packet_info: dict) -> bool | tuple[bool, Any, str] | tuple[bool, None, None]:
    """
    检测 FTP-Patator 爆破：
    """
    if packet_info['dst_port'] != 21 or not packet_info.get('is_login_failure', False):
        return False, None, None

    ip = packet_info['src_ip']
    now = packet_info['timestamp']

    # 记录失败
    _record_failure(ip, now)
    count = len(_fail_times[ip])
    # 更新平滑失败率
    _update_smooth(ip, count)

    # 动态阈值判断
    dynamic_threshold = max(CONFIG["THRESHOLD_MULTIPLIER"] * _smooth_rate[ip], CONFIG["FTP_MIN_THRESHOLD"])
    if count >= dynamic_threshold:
        logger.info(f"FTP-Patator confirmed attack from {ip}, count={count}")
        return True, {"src": ip}, "FTP-Patator"
    elif count >= 0.7 * dynamic_threshold:
        logger.info(f"FTP-Patator suspected attack from {ip}, count={count}")
        return "suspected", {"src": ip}, "FTP-Patator"
    else:
        return False, None, None

def detect_ssh_patator(packet_info: dict) -> bool | tuple[bool, Any, str] | tuple[bool, None, None]:
    """
    检测 SSH-Patator 爆破：
    """
    if packet_info['dst_port'] != 22 or not packet_info.get('is_ssh_handshake_failure', False):
        return False, None, None

    ip = packet_info['src_ip']
    now = packet_info['timestamp']

    _record_failure(ip, now)
    count = len(_fail_times[ip])
    _update_smooth(ip, count)
    dynamic_threshold = max(CONFIG["THRESHOLD_MULTIPLIER"] * _smooth_rate[ip], CONFIG["SSH_MIN_THRESHOLD"])
    if count >= dynamic_threshold:
        logger.info(f"SSH-Patator confirmed attack from {ip}, count={count}")
        return True, {"src": ip}, "SSH-Patator"
    elif count >= 0.7 * dynamic_threshold:
        logger.info(f"SSH-Patator suspected attack from {ip}, count={count}")
        return "suspected", {"src": ip}, "SSH-Patator"
    else:
        return False, None, None