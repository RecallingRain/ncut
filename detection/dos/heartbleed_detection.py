# -*- coding: utf-8 -*-
"""
Heartbleed 攻击检测模块
包含基于规则的实时 Heartbeat 检测和基于 Pyshark 的深度报文解析校验。
可由 detection_manager 统一调用。
"""
import pyshark
from collections import defaultdict
import os
import shutil
import tempfile
from typing import  Optional, Tuple, Any
from pyshark.capture.capture import TSharkCrashException
import logging
from collections import deque
import time
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ========================
# 配置管理
# ========================
CONFIG = {
    'heartbleed_port': 443,
    'pkt_size_limit': 100,
    'pkt_threshold': 10,
    'time_window': 10,
    'deep_interval': 30,  # 最小深度解析间隔（秒）
}

_last_deep_analysis_ts = 0  # 上次深度解析时间戳

def load_config(cfg: dict) -> None:
    """
    更新 Heartbleed 检测参数，cfg 示例：
    {'heartbleed_port': 443, 'pkt_size_limit': 50, 'pkt_threshold': 20, 'time_window': 5}
    """
    if isinstance(cfg, dict):
        CONFIG.update(cfg)

# 实时规则计数队列: 使用 deque 维护滑动窗口
_heartbeat_tracker = defaultdict(lambda: deque())

def clear_state():
    """
    清空 Heartbleed 检测的全局状态，供测试隔离使用。
    """
    for dq in _heartbeat_tracker.values():
        dq.clear()
    _heartbeat_tracker.clear()
    global _last_deep_analysis_ts
    _last_deep_analysis_ts = 0

def detect_heartbleed_rule(packet_info: dict) -> tuple[bool, Optional[str], Optional[str]]:
    """
    基于流量速率的 Heartbeat 请求检测。
    返回 (True, src_ip, 'DoS Heartbleed') 或 (False, None, None)
    """
    # 支持 protocol_num 或 protocol 字段，默认 TCP (6)
    proto = packet_info.get('protocol_num', packet_info.get('protocol', 6))
    # 支持 dst_port 或 port 字段
    dport = packet_info.get('dst_port', packet_info.get('port'))

    if proto != 6 or dport != CONFIG['heartbleed_port']:
        return False, None, None
    if not packet_info.get('is_tls_heartbeat', False):
        return False, None, None

    src_ip = packet_info.get('src_ip')
    ts = packet_info.get('timestamp')
    length = packet_info.get('packet_length', 0)

    # 维护滑动窗口
    window = CONFIG['time_window']
    dq = _heartbeat_tracker[src_ip]
    # 清理过期
    while dq and ts - dq[0] > window:
        dq.popleft()

    # 统计所有 Heartbeat 包
    dq.append(ts)

    # 阈值判断
    thresh = CONFIG['pkt_threshold']
    if len(dq) >= thresh:
        logger.info(f"Heartbleed rule confirmed from {src_ip}: count={len(dq)} threshold={thresh}")
        return True, {'src': src_ip}, 'DoS Heartbleed'
    return False, None, None



import concurrent.futures

def deep_heartbleed_analysis(pcap_file: Optional[str] = None) -> list[Any] | None:
    """
    基于 Pyshark 的离线 Heartbeat 报文解析，返回疑似攻击源 IP 列表。
    """
    # 默认读取当前捕获的 pcap 文件快照
    if pcap_file is None:
        pcap_file = os.path.join("capture_file", "traffic_capture.pcap")
    # 制作 pcap 快照副本（即使原文件不存在也创建临时文件）
    tmp_path = None
    pcap_source = pcap_file
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name
        # 尝试复制原文件到临时文件，若失败就继续使用临时文件空内容
        try:
            shutil.copy(pcap_file, tmp_path)
        except Exception:
            pass
        pcap_source = tmp_path
    except Exception:
        tmp_path = None

    suspicious = set()

    def _run_analysis():
        cap = None
        try:
            cap = pyshark.FileCapture(pcap_source, include_raw=True, use_json=True)
            for pkt in cap:
                try:
                    if hasattr(pkt, 'tls') and getattr(pkt.tls, 'heartbeat', False):
                        suspicious.add(pkt.ip.src)
                        continue
                    if not hasattr(pkt, 'ip') or not hasattr(pkt, 'tcp'):
                        continue
                    raw = pkt.get_raw_packet()
                    if len(raw) < 6:
                        continue
                    if raw[0] != 0x18 or raw[1:3] not in (b'\x03\x02', b'\x03\x03'):
                        continue
                    hb_type = raw[5]
                    if hb_type != 1:
                        continue
                    suspicious.add(pkt.ip.src)
                except (AttributeError, IndexError):
                    continue
        finally:
            if cap is not None:
                try:
                    cap.close()
                except:
                    pass
        return list(suspicious)

    timeout = CONFIG.get('deep_timeout', 60)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_run_analysis)
            suspects = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError as e:
        logger.warning(f"Deep heartbleed analysis timed out: {e}")
        suspects = []
    except (TSharkCrashException, OSError) as e:
        logger.warning(f"Deep heartbleed analysis failed: {e}")
        suspects = []
    # Clean up temporary file
    if tmp_path is not None:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return suspects


def detect_heartbleed_attacks(packet_info: dict, pcap_file: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    二次验证接口：先调速率规则，再离线解析。
    pcap_file: 可选的流量文件路径，用于深度校验，默认为捕获模块的 PCAP_FILE。
    """
    # 第一阶段：快速规则
    is_attack, extra, attack_type = detect_heartbleed_rule(packet_info)
    # 若规则返回疑似，则直接返回疑似
    if is_attack == "suspected":
        return is_attack, extra, attack_type
    # 若规则未命中，直接返回
    if not is_attack:
        return False, None, None
    # 规则命中，进行深度确认
    global _last_deep_analysis_ts
    interval = CONFIG.get('deep_interval', 30)
    now = time.time()
    if now - _last_deep_analysis_ts < interval:
        return is_attack, extra, attack_type
    _last_deep_analysis_ts = now
    try:
        suspects = deep_heartbleed_analysis(pcap_file)
        if extra.get('src') in suspects:
            return True, extra['src'], attack_type
        else:
            return False, None, None
    except (TSharkCrashException, OSError, TimeoutError):
        logger.warning("Deep heartbleed analysis failed during confirmation")
        return True, extra['src'], attack_type


__all__ = [
    'load_config',
    'detect_heartbleed_rule',
    'deep_heartbleed_analysis',
    'detect_heartbleed_attacks',
    'clear_state',
]
