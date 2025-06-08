from collections import deque
from datetime import datetime

import logging

logger = logging.getLogger(__name__)


# ========================
# 配置管理
# ========================
CONFIG = {
    'hulk_threshold': 120,
    'hulk_time_window': 1,
    'goldeneye_time_window': 5,
    'goldeneye_request_threshold': 80,
    'slowloris_conn_window': 10,
    'slowloris_syn_threshold': 20,
    'slowhttp_time_window': 10,
    'slowhttp_packet_size_threshold': 50,
    'slowhttp_count_threshold': 15,
    'dyn_divisor': 5,  # 动态阈值除数
}

def clear_state():
    """清空所有滑动窗口状态，供测试和重置使用"""
    global_tracker.deque.clear()
    hulk_window.deque.clear()
    goldeneye_window.deque.clear()
    slowloris_window.deque.clear()
    slowhttp_window.deque.clear()


def load_config(cfg: dict) -> None:
    """
    更新 CONFIG，并同步更新所有滑动窗口实例的窗口大小
    """
    if not isinstance(cfg, dict):
        return
    CONFIG.update(cfg)
    # 更新各滑动窗口的 window_size
    _update_windows()


# ========================
# 滑动窗口辅助类
# ========================
class SlidingWindow:
    """
    用于维护滑动时间窗口内的时间戳队列，自动清理过期数据
    """
    def __init__(self, window_size: float):
        self.window_size = window_size
        self.deque = deque()

    def update_window(self, window_size: float) -> None:
        self.window_size = window_size

    def append(self, ts: float) -> None:
        # Normalize timestamp to float seconds since epoch
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts).timestamp()
            except ValueError:
                ts = float(ts)
        else:
            ts = float(ts)
        self.deque.append(ts)
        self._clean(ts)

    def _clean(self, ts: float) -> None:
        # 移除所有早于 ts-window_size 的时间戳
        while self.deque and ts - self.deque[0] > self.window_size:
            self.deque.popleft()

    def count(self) -> int:
        return len(self.deque)


# ========================
# 各模块滑动窗口实例初始化
# ========================
# 全局请求滑动窗口，window_size 取所有子模块最大值
_global_window_size = max(
    CONFIG['hulk_time_window'],
    CONFIG['goldeneye_time_window'],
    CONFIG['slowloris_conn_window'],
    CONFIG['slowhttp_time_window'],
)
global_tracker = SlidingWindow(_global_window_size)

hulk_window = SlidingWindow(CONFIG['hulk_time_window'])
goldeneye_window = SlidingWindow(CONFIG['goldeneye_time_window'])
slowloris_window = SlidingWindow(CONFIG['slowloris_conn_window'])
slowhttp_window = SlidingWindow(CONFIG['slowhttp_time_window'])


def _update_windows() -> None:
    """内部：当 CONFIG 更新后，同步调整滑动窗口大小"""
    global _global_window_size
    _global_window_size = max(
        CONFIG['hulk_time_window'],
        CONFIG['goldeneye_time_window'],
        CONFIG['slowloris_conn_window'],
        CONFIG['slowhttp_time_window'],
    )
    global_tracker.update_window(_global_window_size)
    hulk_window.update_window(CONFIG['hulk_time_window'])
    goldeneye_window.update_window(CONFIG['goldeneye_time_window'])
    slowloris_window.update_window(CONFIG['slowloris_conn_window'])
    slowhttp_window.update_window(CONFIG['slowhttp_time_window'])


# ========================
# 动态阈值计算
# ========================
def get_dynamic_threshold(base: int) -> int:
    """
    根据过去窗口内的总请求数，自适应平滑阈值
    """
    total = global_tracker.count()
    return max(base, int(total / CONFIG['dyn_divisor']))


# ========================
# 子检测函数公用逻辑
# ========================
def _check_threshold(
    src_ip: str,
    window: SlidingWindow,
    ts: float,
    base_threshold: int,
    attack_type: str
):
    """
    公共：按滑动窗口累积计数并判断是否超过阈值
    """
    window.append(ts)
    count = window.count()
    dyn = get_dynamic_threshold(base_threshold)
    # 日志记录
    logger.debug(f"{attack_type} check: src={src_ip}, count={count}, base={base_threshold}, dyn={dyn}")
    # 确认攻击
    if count > dyn:
        logger.info(f"{attack_type} confirmed attack from {src_ip}, count={count}, dyn={dyn}")
        return True, {'src': src_ip}, attack_type
    # 疑似攻击
    if count > base_threshold:
        logger.info(f"{attack_type} suspected attack from {src_ip}, count={count}, base={base_threshold}")
        return "suspected", {'src': src_ip}, attack_type
    # 正常流量
    return False, None, None


# ========================
# DoS 子检测器
# ========================

def detect_dos_hulk(packet_info: dict):
    """
    检测 DoS Hulk 攻击：高频 TCP 请求
    """
    if packet_info.get('protocol_num') != 6:
        return False, None, None
    if packet_info.get('dst_port') not in (80, 443):
        return False, None, None

    ts = packet_info.get('timestamp')
    src_ip = packet_info.get('src_ip')
    # 全局窗口先更新
    global_tracker.append(ts)
    return _check_threshold(
        src_ip, hulk_window, ts,
        CONFIG['hulk_threshold'], 'DoS Hulk'
    )


def detect_dos_goldeneye(packet_info: dict):
    """
    检测 DoS GoldenEye 攻击：短时间高频连接
    """
    if packet_info.get('protocol_num') != 6:
        return False, None, None
    if packet_info.get('dst_port') not in (80, 443):
        return False, None, None

    ts = packet_info.get('timestamp')
    src_ip = packet_info.get('src_ip')
    global_tracker.append(ts)
    return _check_threshold(
        src_ip, goldeneye_window, ts,
        CONFIG['goldeneye_request_threshold'], 'DoS GoldenEye'
    )


def detect_dos_slowloris(packet_info: dict):
    """
    检测 DoS Slowloris 攻击：大量 SYN 报文且不完成握手
    """
    if packet_info.get('protocol_num') != 6:
        return False, None, None
    if packet_info.get('dst_port') not in (80, 443):
        return False, None, None

    flags = packet_info.get('flags', '')
    # 仅纯 SYN 包
    if 'S' not in flags or 'A' in flags:
        return False, None, None

    ts = packet_info.get('timestamp')
    src_ip = packet_info.get('src_ip')
    global_tracker.append(ts)
    return _check_threshold(
        src_ip, slowloris_window, ts,
        CONFIG['slowloris_syn_threshold'], 'DoS Slowloris'
    )


def detect_dos_slowhttptest(packet_info: dict):
    """
    检测 DoS Slowhttptest 攻击：慢速 HTTP 小包积累
    """
    if packet_info.get('protocol_num') != 6:
        return False, None, None
    if packet_info.get('dst_port') not in (80, 443):
        return False, None, None

    pkt_len = packet_info.get('packet_length', 0)
    if pkt_len >= CONFIG['slowhttp_packet_size_threshold']:
        return False, None, None

    ts = packet_info.get('timestamp')
    src_ip = packet_info.get('src_ip')
    global_tracker.append(ts)
    return _check_threshold(
        src_ip, slowhttp_window, ts,
        CONFIG['slowhttp_count_threshold'], 'DoS Slowhttptest'
    )


# ========================
# DoS 统一检测入口
# ========================
def detect_dos_attacks(packet_info: dict):
    """
    按顺序调用所有 DoS 子检测器，返回首个检测结果
    """
    for fn in [
        detect_dos_hulk,
        detect_dos_goldeneye,
        detect_dos_slowloris,
        detect_dos_slowhttptest,
    ]:
        res = fn(packet_info)
        if res[0] not in (False, None):
            return res
    return False, None, None


__all__ = [
    'load_config',
    'detect_dos_hulk',
    'detect_dos_goldeneye',
    'detect_dos_slowloris',
    'detect_dos_slowhttptest',
    'detect_dos_attacks',
]
