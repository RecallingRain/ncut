from collections import defaultdict
import time
from collections import deque
import logging
logger = logging.getLogger(__name__)
# 专用 DDoS 日志处理器，仅记录本模块日志
handler = logging.FileHandler('ddos.log')
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)
# 不向上传播到 root logger
logger.propagate = False

# ========================
# 配置与状态管理
# ========================

# 运行时可通过 load_config 从 YAML 覆盖以下默认规则参数
CONFIG = {
    'per_ip_high_threshold': 80,
    'active_ip_suspicious_threshold': 50,
    'active_ip_high_threshold': 80,
    'window_size': 30,  # 滑动窗口大小（秒）
    'smoothing_alpha': 0.05,
    'threshold_high_factor': 1.4,
    'threshold_suspicious_factor': 0.5,
    'pkt_high_threshold': 1000,
}  # key: 含义

# 滑动窗口分片计数，每个桶代表一秒内每个 src_ip 的包数
window_size = CONFIG['window_size']
buckets = deque([defaultdict(int) for _ in range(window_size)], maxlen=window_size)
_current_bucket_time: float | None = None

# 指数移动平均后计算的平均活跃 IP 数，用于平滑动态阈值
_avg_active_ip_count: float = 0.0

from typing import Any, Union


# 全局状态：每个 IP 的请求计数
_ddos_ip_counts = defaultdict(int)


def reset_ddos_state() -> None:
    """
    清空 DDoS 检测模块的全局状态，包括：
    - _ddos_ip_counts: 源 IP 计数字典
    - _avg_active_ip_count: 平滑平均值
    - _packet_events: 滑动窗口事件队列
    """
    global _ddos_ip_counts, _avg_active_ip_count
    _ddos_ip_counts = defaultdict(int)  # 清空 IP 计数字典
    _avg_active_ip_count = 0.0           # 重置平滑平均活跃 IP 数
    # 重置分片桶和时间指针
    global buckets, _current_bucket_time
    buckets = deque([defaultdict(int) for _ in range(CONFIG['window_size'])], maxlen=CONFIG['window_size'])
    _current_bucket_time = None


def load_config(cfg: dict) -> None:
    """
    从传入的 cfg 字典更新模块参数。
    """
    if not isinstance(cfg, dict):
        return
    CONFIG.update(cfg)


def detect_ddos(packet_info: Any) -> Union[bool, str]:
    # 本函数仅返回检测结果，不执行任何 I/O 操作

    # 获取源IP，支持 dict 和对象两种格式
    if isinstance(packet_info, dict):
        src_ip = packet_info.get('src_ip')
    else:
        src_ip = packet_info.src_ip

    # 过滤掉无效或缺失的 src_ip
    if not src_ip:
        logger.debug("Invalid src_ip, skipping DDoS detection")
        return False

    # 获取当前时间戳
    now = time.time()
    window_size = CONFIG['window_size']

    global buckets, _current_bucket_time, _ddos_ip_counts
    now_sec = int(now)
    logger.debug(f"Step 1: timestamp={now}, now_sec={now_sec}")
    # 初始化时间指针
    if _current_bucket_time is None:
        _current_bucket_time = now_sec
    # 如果跨秒，则滚动 bucket，并更新全局计数
    elapsed = now_sec - _current_bucket_time
    logger.debug(f"Rolling buckets: elapsed={elapsed}, current_bucket_time={_current_bucket_time}")
    for _ in range(min(elapsed, CONFIG['window_size'])):
        old_bucket = buckets.popleft()
        logger.debug(f"   Removing old bucket counts: {old_bucket}")
        # 扣减老桶内各 IP 的计数
        for ip, cnt in old_bucket.items():
            _ddos_ip_counts[ip] -= cnt
            if _ddos_ip_counts[ip] <= 0:
                del _ddos_ip_counts[ip]
        buckets.append(defaultdict(int))
    _current_bucket_time = now_sec

    # 将当前包计入最新桶，并更新全局 IP 计数
    buckets[-1][src_ip] += 1
    _ddos_ip_counts[src_ip] += 1
    logger.debug(f"Step 2: packet from {src_ip} added: bucket_count={buckets[-1][src_ip]}, total_count={_ddos_ip_counts[src_ip]}")

    # 基于同一秒桶计数的即时单个IP突发检测
    per_ip_thresh = CONFIG.get('per_ip_high_threshold', 0)
    if buckets[-1][src_ip] > per_ip_thresh:
        logger.info(
            f"Decision: ATTACK (per-IP burst: bucket_count={buckets[-1][src_ip]} > per_ip_high_threshold={per_ip_thresh})"
        )
        return True

    # 统计窗口内的 unique_ips、active_ip_count
    #    unique_ips: 当前窗口内不同的源 IP 集合
    #    active_ip_count: 当前窗口内活跃的不同 IP 数量
    unique_ips = set(_ddos_ip_counts.keys())
    active_ip_count = len(unique_ips)
    logger.debug(f"Step 4: active_ip_count={active_ip_count}, unique_ips={unique_ips}")
    # total_packets 仅用于包速率判断

    # 指数移动平均更新 _avg_active_ip_count，用于平滑动态阈值
    alpha = CONFIG['smoothing_alpha']
    global _avg_active_ip_count
    _avg_active_ip_count = alpha * active_ip_count + (1 - alpha) * _avg_active_ip_count
    logger.debug(f"Step 5: updated _avg_active_ip_count={_avg_active_ip_count}")
    # —— 冷启动保护 ——
    # 当平滑后的活跃 IP 数仍然很小（<5）时视为系统正在暖机，不进行可疑/攻击判定
    if _avg_active_ip_count < 5:
        return False

    # 动态高、低阈值计算过程及用途：
    #    动态高阈值 = max(固定高阈值, 平滑平均活跃 IP 数 * 高阈值因子)
    #    动态低阈值 = **max**(固定低阈值, 平滑平均活跃 IP 数 * 低阈值因子)

    high_factor = CONFIG['threshold_high_factor']
    susp_factor = CONFIG['threshold_suspicious_factor']
    logger.debug(f"Threshold factors: high_factor={high_factor}, susp_factor={susp_factor}")
    dynamic_high: int = int(max(
        CONFIG['active_ip_high_threshold'],
        _avg_active_ip_count * high_factor
    ))
    dynamic_suspicious: int = int(max(
        CONFIG['active_ip_suspicious_threshold'],
        _avg_active_ip_count * susp_factor
    ))
    logger.debug(f"Step 6: dynamic_high={dynamic_high}, dynamic_suspicious={dynamic_suspicious}")
    # 返回 True/False/"suspected" 含义：

    if active_ip_count > dynamic_high:
        logger.info(f"Decision: ATTACK (active_ip_count={active_ip_count} > dynamic_high={dynamic_high})")
        return True
    elif active_ip_count < dynamic_suspicious:
        logger.info(f"Decision: NORMAL (active_ip_count={active_ip_count} < dynamic_suspicious={dynamic_suspicious})")
        return False
    else:
        logger.info(f"Decision: SUSPECTED (dynamic_suspicious={dynamic_suspicious} <= active_ip_count={active_ip_count} <= dynamic_high={dynamic_high})")
        # fallback: check single IP burst
        if _ddos_ip_counts[src_ip] > CONFIG.get('per_ip_high_threshold', 0):
            logger.info(f"Decision: ATTACK (per_ip count exceeded threshold after dynamic check)")
            return True
        # fallback: check overall packet rate
        packet_rate = sum(_ddos_ip_counts.values()) / window_size
        if packet_rate > CONFIG.get('pkt_high_threshold', 0):
            logger.info(f"Decision: ATTACK (packet_rate exceeded pkt_high_threshold after dynamic check)")
            return True
        return "suspected"


def detect_ddos_attacks(packet_info: Any) -> tuple[bool, dict[str, Any], str] | tuple[bool, None, None] | tuple[
    str, dict[str, Any], str]:
    """
    规则检测 DDoS 攻击接口
    """
    # 调用 detect_ddos 获取基础检测结果
    result = detect_ddos(packet_info)
    # 提取攻击源 IP
    attacker_ip = packet_info['src_ip'] if isinstance(packet_info, dict) else packet_info.src_ip

    if result is True:
        # 确认 DDoS 攻击
        return True, {"src": attacker_ip}, "DDoS"
    elif result is False:
        # 正常流量
        return False, None, None
    else:
        # 疑似 DDoS 攻击
        return "suspected", {"src": attacker_ip}, "DDoS"


__all__ = ["reset_ddos_state", "detect_ddos", "load_config", "detect_ddos_attacks"]
