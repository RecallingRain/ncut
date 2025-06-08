import re
from collections import defaultdict, deque
from statistics import variance
import logging

logger = logging.getLogger('botnet_ares')
logger.setLevel(logging.DEBUG)
# 防止消息传播到根记录器
logger.propagate = False
# 从botnet中删除所有现有的处理程序
for h in list(logger.handlers):
    logger.removeHandler(h)
# 创建仅记录botnet的日志
handler = logging.FileHandler('botnet.log')
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)
handler.setFormatter(formatter)
logger.addHandler(handler)

# 模块全局配置（从yaml读取）
CONFIG = {
    'periodic_threshold': 12,
    'interval_variance_threshold': 1.5,
    'target_ip_threshold': 15,
    'irc_port': 6667,
    'command_patterns': [r'\bJOIN\b', r'\bPING\b', r'\bPONG\b', r'\bNICK\b', r'\bUSER\b'],
    'suspected_cooldown': 60,
}

# 预编译命令模式，避免每次调用重新编译
COMPILED_COMMAND_PATTERNS = [re.compile(p, re.I) for p in CONFIG['command_patterns']]

# 存储历史通信记录，deque长度会在检测时动态限制
traffic_history = defaultdict(lambda: defaultdict(deque))
target_ip_counts = defaultdict(set)

# 缓存疑似警报时间，防止短期内重复报警
suspected_cache = {}

def clear_state():
    """清空全局缓存，供单元测试或定期重置使用"""
    traffic_history.clear()
    target_ip_counts.clear()
    suspected_cache.clear()

def init_config(cfg):
    """从yaml中读取阈值配置"""
    global CONFIG
    CONFIG.update(cfg)

def _should_alert_suspected(src_ip, timestamp):
    """
    判断此时是否应该触发一次疑似警报，
    如果距离上次警报未超过冷却期，返回 False
    否则更新缓存时间并返回 True
    """
    cooldown = CONFIG.get('suspected_cooldown', 60)
    last = suspected_cache.get(src_ip)
    if last is not None and timestamp - last < cooldown:
        return False
    suspected_cache[src_ip] = timestamp
    return True

def _is_irc_flow(protocol, dst_port):
    return protocol == "IRC" or dst_port == CONFIG['irc_port']

def detect_botnet_ares(packet_info):
    """
    检测单个数据包是否属于Botnet Ares攻击流量
    """

    src_ip   = packet_info['src_ip']
    dst_ip   = packet_info['dst_ip']
    if src_ip is None or dst_ip is None:
        logger.debug("Skipping packet with missing src_ip or dst_ip")
        return False, None, None
    dst_port = packet_info['dst_port']
    protocol = packet_info['protocol']
    payload_bytes = packet_info.get('payload_raw_bytes', b'')
    payload = payload_bytes.decode('utf-8', errors='ignore')
    timestamp= packet_info['timestamp']

    logger.debug(f"Received packet: src_ip={src_ip}, dst_ip={dst_ip}, dst_port={dst_port}, protocol={protocol}, timestamp={timestamp}")

    # --- 特征1：指令特征检测（要求至少两种IRC指令出现） ---
    logger.debug("Feature1: Checking IRC command patterns")
    if _is_irc_flow(protocol, dst_port):
        matches = [pat.search(payload) for pat in COMPILED_COMMAND_PATTERNS]
        matches = [m for m in matches if m]
        if len(matches) >= 2 and len(payload) > 50:
            if _should_alert_suspected(src_ip, timestamp):
                logger.info(f"Suspected alert triggered by Feature1 for src_ip={src_ip}")
                return "suspected", {"src": src_ip}, "Botnet Ares"

    if not _is_irc_flow(protocol, dst_port):
        logger.debug("Skipping periodic check for non-IRC flow")
    else:
        logger.debug("Feature2: Checking periodic communication patterns")
        # --- 特征2：周期性通信检测 ---
        history = traffic_history[src_ip][dst_ip]
        history.append(timestamp)
        # 保留最近 periodic_threshold 次通信
        maxlen = CONFIG.get('periodic_threshold', len(history))
        while len(history) > maxlen:
            history.popleft()
        if len(history) >= maxlen:
            intervals = [t2 - t1 for t1, t2 in zip(history, list(history)[1:])]
            if len(intervals) >= 5 and variance(intervals) <= CONFIG['interval_variance_threshold']:
                if _should_alert_suspected(src_ip, timestamp):
                    logger.info(f"Suspected alert triggered by Feature2 for src_ip={src_ip}")
                    return "suspected", {"src": src_ip}, "Botnet Ares"

    logger.debug("Feature3: Checking HTTP User-Agent anomalies")
    # --- 特征3：IRC端口或HTTP异常User-Agent检测 ---
    # 对纯端口判断也加上命令或UA校验，避免大面触发
    if protocol == "HTTP":
        suspicious_agents = ['aresbot', 'zombie-client', 'evil-bot']
        ua_match = re.search(r'User-Agent:\s*([^\r\n]+)', payload, re.I)
        if ua_match:
            ua = ua_match.group(1).lower()
            if any(s in ua for s in suspicious_agents):
                if _should_alert_suspected(src_ip, timestamp):
                    logger.info(f"Suspected alert triggered by Feature3 for src_ip={src_ip}")
                    return "suspected", {"src": src_ip}, "Botnet Ares"

    logger.debug("Feature4: Checking target IP concentration")
    # --- 特征4：目标集中检测（真正的攻击确认，仅限 IRC/IRC-port 流量） ---
    target_ip_counts[dst_ip].add(src_ip)
    if _is_irc_flow(protocol, dst_port) and len(target_ip_counts[dst_ip]) >= CONFIG['target_ip_threshold']:
        logger.info(f"Confirmed attack: target_ip={dst_ip}, unique_src_count={len(target_ip_counts[dst_ip])}")
        # 确认攻击，直接返回 True
        return True, {"src": src_ip}, "Botnet Ares"

    logger.debug("No botnet behavior detected for this packet")
    # 未检测到异常，正常流量
    return False, None, None
