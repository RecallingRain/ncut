# -*- coding: utf-8 -*-
"""
PortScan 检测模块

通过调用 init_config(cfg) 加载阈值配置，并在滑动窗口内实时检测端口扫描攻击。
返回 (False, None, None)、("suspected", extra_info, "PortScan") 或 (True, extra_info, "PortScan")。
"""

from collections import defaultdict, deque
import logging
logger = logging.getLogger(__name__)

# —— 模块全局默认配置 ——
CONFIG = {
    'window_size': 30,
    'port_threshold': 60,
    'failure_ratio_threshold': 0.6,
    'suspected_margin': {
        'port_lower': 40,
        'failure_lower': 0.4
    }
}

# —— 工具函数 ——
def _to_number(v):
    """尝试把字符串数字转成 int / float；否则原值返回"""
    if isinstance(v, str) and v.strip():
        if v.isdigit():
            return int(v)
        try:
            return float(v)
        except ValueError:
            return v     # 非数字字符串
    return v


def init_config(cfg: dict):
    """
    从上层传入的 cfg 中合并阈值配置（支持嵌套字典深度更新）
    并把 YAML 里可能以字符串形式出现的数字转换成 int/float。
    """
    def deep_update(dst, src):
        for k, v in src.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                deep_update(dst[k], v)
            else:
                dst[k] = _to_number(v)
    deep_update(CONFIG, cfg or {})


# —— 状态存储 ——
ip_events = defaultdict(lambda: deque())


def clear_state():
    """清空内部状态，方便单元测试时隔离用例"""
    ip_events.clear()


def detect_portscan(packet_info: dict):
    """
    检测 PortScan 攻击。

    参数:
      packet_info:
        - timestamp (float): 报文时间戳（秒级）
        - src_ip    (str)  : 源 IP
        - dst_ip    (str)  : 目的 IP
        - failure_flag (bool): 本次探测是否失败（True=RST/无响应，False=成功握手）

    返回:
      - status: False / "suspected" / True
      - extra_info: { src_ip, port_count, failure_rate, scan_type }
      - attack_type: "PortScan" 或 None
    """
    ts = packet_info.get('timestamp')
    src = packet_info.get('src_ip')
    dst = packet_info.get('dst_ip')
    failure = packet_info.get('failure_flag', False)

    # 类型安全转换 timestamp
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False, None, None

    # 支持多种字符串形式的 failure_flag
    if isinstance(failure, str):
        failure_str = failure.strip().lower()
        failure = failure_str in ("1", "true", "yes")
    else:
        failure = bool(failure)

    # 简单校验
    if src is None or dst is None:
        return False, None, None

    # 更新该 src_ip 的事件队列
    events = ip_events[src]
    events.append((ts, failure, dst))
    # 清理过期事件
    window_size = _to_number(CONFIG.get('window_size', 60)) or 60
    while events and ts - events[0][0] > window_size:
        events.popleft()

    port_count = len(events)
    failure_count = sum(1 for _, f, _ in events if f)
    failure_rate = (failure_count / port_count) if port_count else 0.0

    # 判断扫描类型
    dst_set = {d for _, _, d in events}
    scan_type = 'horizontal' if len(dst_set) == 1 else 'vertical'

    extra_info = {
        'src': src,
        'port_count': port_count,
        'failure_rate': failure_rate,
        'scan_type': scan_type
    }

    attack_type = CONFIG.get('attack_type', 'PortScan')

    # 确认攻击
    if port_count >= _to_number(CONFIG['port_threshold']) and failure_rate >= _to_number(CONFIG['failure_ratio_threshold']):
        logger.warning(f"PortScan 确认: src={src}, count={port_count}, rate={failure_rate:.2f}, type={scan_type}")
        return True, extra_info, attack_type

    # 疑似攻击
    suspected = CONFIG.get('suspected_margin', {})
    if port_count >= _to_number(suspected.get('port_lower', 0)) and failure_rate >= _to_number(suspected.get('failure_lower', 0)):
        logger.info(f"PortScan 疑似: src={src}, count={port_count}, rate={failure_rate:.2f}, type={scan_type}")
        return "suspected", extra_info, attack_type

    # 正常流量
    return False, None, None
