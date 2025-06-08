"""
infiltration_detection.py
~~~~~~~~~~~~~~~~~~~~~~~~~
渗透攻击（Infiltration）检测模块

返回三元组格式约定
----------------
- 正常流量    : (False, None, None)
- 确认攻击    : (True,  extra_info: dict, "Infiltration")
- 疑似攻击    : ("suspected", extra_info: dict, "Infiltration")
"""
from __future__ import annotations

import math
import re
import time
import ipaddress
import statistics
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any, Deque, Set

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

try:
    from pybloom_live import ScalableBloomFilter
except ImportError:  # 允许缺失依赖，但提示用户
    raise RuntimeError(
        "缺少依赖 pybloom_live，请先运行 `pip install pybloom_live` 后再启动检测模块"
    )

try:
    import tldextract
except ImportError:
    raise RuntimeError(
        "缺少依赖 tldextract，请先运行 `pip install tldextract` 后再启动检测模块"
    )


# --------------------------------------------------------------------------- #
# ⬇⬇⬇                 1. 工具函数 & 常量定义                                #
# --------------------------------------------------------------------------- #
_DOMAIN_RE = re.compile(rb"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}", re.I)

__all__ = ["InfiltrationDetector", "init_config", "detect_infiltration"]


def _shannon_entropy(s: str) -> float:
    """计算 Shannon 信息熵，忽略大小写。"""
    s = s.lower()
    freq = Counter(s)
    length = len(s)
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in freq.values())


def _utcnow_ts() -> float:
    """当前 UTC 时间戳（float 秒）。"""
    return time.time()


def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# ⬇⬇⬇                 2. 统计器组件                                          #
# --------------------------------------------------------------------------- #
class RareDomainTracker:
    """
    稀有域名 / 可疑 IP 追踪器

    逻辑：
        1. 尝试从 DNS / TLS / HTTP Payload 中提取域名字符串；
        2. 计算熵值，大于阈值认为可疑；
        3. 若布隆过滤器中未曾出现 → 标记 “稀有”。
    """

    def __init__(self, entropy_th: float, window_minutes: int):
        self.entropy_th = entropy_th
        self.window = timedelta(minutes=window_minutes)
        self.bloom = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
        self.last_seen: Dict[str, float] = {}  # domain -> last_ts
        self._bloom_reset_ts = _utcnow_ts()

    def _extract_domain(self, payload: bytes) -> str | None:
        """从原始载荷中粗略解析域名（正则方式，通用但可能有误报）。"""
        # 若 payload 太短或已知无域名，跳过
        if len(payload) < 32:
            return None
        if not hasattr(self, '_fail_cache'):
            self._fail_cache = set()
        key = payload[:16]
        if key in self._fail_cache:
            return None
        match = _DOMAIN_RE.search(payload)
        if not match:
            self._fail_cache.add(key)
            return None
        # 使用 tldextract 提取完整注册域名及子域
        domain = match.group(0).decode(errors="ignore")
        tld_info = tldextract.extract(domain)
        registered = f"{tld_info.domain}.{tld_info.suffix}"
        if tld_info.subdomain:
            full = f"{tld_info.subdomain}.{registered}"
            return full
        return registered

    # public ------------------------------------------------------------ #
    def update_and_check(self, packet_info: Dict[str, Any]) -> bool:
        """
        更新内部状态并返回是否命中【稀有域名】规则。

        Returns
        -------
        bool
            True  -> 稀有域名且熵值高
            False -> 无异常
        """
        payload_raw: bytes | str | None = packet_info.get("payload_raw_bytes")
        if payload_raw is None:
            return False

        now_ts = packet_info.get("timestamp", _utcnow_ts())
        # 解析时间戳字符串或转换为浮点数
        if isinstance(now_ts, str):
            try:
                now_ts = datetime.fromisoformat(now_ts).timestamp()
            except ValueError:
                now_ts = float(now_ts)
        else:
            now_ts = float(now_ts)

        # 滑窗失效检查：若包的时间早于 current_time - window，则不触发稀有域名
        cutoff = _utcnow_ts() - self.window.total_seconds()
        if now_ts < cutoff:
            return False

        # 每日重建 Bloom 过滤器
        if now_ts - self._bloom_reset_ts > 86400:
            logger.debug(f"重建 Bloom 过滤器，当前时间 {now_ts}, 上次重建 {self._bloom_reset_ts}")
            self.bloom = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH)
            self._bloom_reset_ts = now_ts

        # 尝试提取一个域；如果没有，我们将回退到原始有效载荷熵
        raw_domain = self._extract_domain(payload_raw)
        if raw_domain:
            domain = raw_domain
            ent = _shannon_entropy(domain)
        else:
            # 尝试将载荷解码为文本并计算熵
            try:
                if isinstance(payload_raw, (bytes, bytearray)):
                    text_str = payload_raw.decode(errors="ignore")
                else:
                    text_str = str(payload_raw)
            except Exception:
                return False
            if not text_str:
                return False
            domain = None
            ent = _shannon_entropy(text_str)
        # 熵滤波器
        if ent <= self.entropy_th:
            return False

        # 如果可用，则使用域，否则使用 text_str 来实现bloom/唯一性
        key = domain if domain is not None else text_str
        # 如果已经看到bloom, 跳过
        if key in self.bloom:
            return False
        self.bloom.add(key)
        # 记录最新出现时间并清理过期
        self.last_seen[key] = now_ts
        self._evict_old(now_ts)
        return True

    # private ----------------------------------------------------------- #
    def _evict_old(self, now_ts: float):
        expiry_ts = now_ts - self.window.total_seconds()
        expired = [d for d, ts in self.last_seen.items() if ts < expiry_ts]
        for d in expired:
            del self.last_seen[d]
        # 无需从 Bloom 中移除（允许微小假阳），Bloom 自增长不会无限膨胀


class AbnormalTransferStat:
    """
    出站 / 入站流量比例异常检测

    思路：
        - 维护每个 src_ip 的 “出站字节序列 deque”，窗口 30 min；
        - 对当前点计算 z-score，若超过阈值则标记异常。

    出站判定：
        - 若 src_ip 为内网 (private) 且 dst_ip 为公网，则计入 outbound；
        - 若 src_ip 为公网且 dst_ip 为私网，则 inbound 到同一私网主机；
        - 其余情况（内网→内网 / 公网→公网）忽略。
    """

    def __init__(self, z_th: float, window_minutes: int = 30):
        self.z_th = z_th
        self.window = timedelta(minutes=window_minutes)
        # {ip: deque[(timestamp, bytes_out)]}
        self.out_series: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self.bytes_out_current_minute: Dict[str, int] = defaultdict(int)

    def update_and_check(self, packet_info: Dict[str, Any]) -> bool:
        ts = packet_info.get("timestamp")  # 可能是 float/int 或 ISO 字符串
        if ts is None:
            now_ts = _utcnow_ts()
        else:
            now_ts = float(ts) if isinstance(ts, (int, float)) else datetime.fromisoformat(ts).timestamp()

        src_ip, dst_ip = packet_info.get("src_ip"), packet_info.get("dst_ip")
        if not src_ip or not dst_ip:
            return False

        # 删除私有/公共 IP 过滤——考虑所有流量是否存在异常传输

        pkt_len = int(packet_info.get("packet_length", 0))
        if pkt_len <= 0:
            return False

        # 按分钟聚合，减少样本量并过滤抖动
        minute_bucket = int(now_ts // 60)
        key = (src_ip, minute_bucket)
        self.bytes_out_current_minute[key] += pkt_len

        # 检测任意旧分钟桶并 flush
        flushed = False
        for old_key in list(self.bytes_out_current_minute.keys()):
            if old_key[0] == src_ip and old_key != key:
                total_prev_minute = self.bytes_out_current_minute.pop(old_key)
                self.out_series[src_ip].append((old_key[1] * 60.0, total_prev_minute))
                # 清理过期
                self._evict_old(src_ip, now_ts)
                logger.debug(f"Minute boundary reached (any gap): src={src_ip}, prev_bytes={total_prev_minute}")
                flushed = True
                break


        if flushed:
            # 刷新后
            series = [b for _, b in self.out_series[src_ip]]
            # 单样本场景：如果当前桶（或上分钟流量） 大于 series[0] * z_th，即为短时峰值
            cur_total = self.bytes_out_current_minute.get(key, 0)
            if len(series) == 1 and cur_total > series[0] * self.z_th:
                logger.debug(
                    f"Abnormal transfer detected (single-sample burst): src={src_ip}, prev={series[0]}, cur={cur_total}")
                return True
            # 多样本场景继续使用之前的基线或 Z-score
            series = [b for _, b in self.out_series[src_ip]]
            # 单分钟突发峰值检测：将冲洗的样品与基线进行比较
            baseline = series[-2] if len(series) >= 2 else 0
            if baseline > 0 and total_prev_minute > baseline * self.z_th:
                logger.debug(f"Abnormal transfer detected (burst peak): src={src_ip}, baseline={baseline}, prev_bytes={total_prev_minute}")
                return True
            # 如果有足够的历史记录，则进行多样本 z-score检测
            if len(series) >= 3:
                mean_val = statistics.mean(series)
                stdev_val = statistics.stdev(series)
                if stdev_val == 0:
                    if total_prev_minute > mean_val * self.z_th:
                        logger.debug(
                            f"Abnormal transfer detected (peak z=N/A): src={src_ip}, flushed_bytes={total_prev_minute}")
                        return True
                else:
                    z_score = (total_prev_minute - mean_val) / stdev_val
                    if z_score > self.z_th:
                        logger.debug(
                            f"Abnormal transfer detected (peak z): src={src_ip}, flushed_bytes={total_prev_minute}, z_score={z_score}")
                        return True

        # -------- 在“当前分钟”实时检查 z-score --------
        cur_total = self.bytes_out_current_minute[key]
        series = [b for _, b in self.out_series[src_ip]]
        # 有 ≥3 个历史样本即可形成初步基线
        if len(series) >= 3:
            mean_val = statistics.mean(series)
            stdev_val = statistics.stdev(series)
            if stdev_val == 0:  # 无波动时走倍数判定
                if cur_total > mean_val * self.z_th:
                    logger.debug(f"Abnormal transfer detected: src={src_ip}, bytes={cur_total}, z_score=N/A")
                    return True
            else:
                z_score = (cur_total - mean_val) / stdev_val
                if z_score > self.z_th:
                    logger.debug(f"Abnormal transfer detected: src={src_ip}, bytes={cur_total}, z_score={z_score}")
                    return True

        return False
    def force_minute_flush(self, src_ip: str, minute_bucket: int) -> int:
        """
        测试钩子：手动将指定 src_ip 的 minute_bucket 数据写入 out_series 并清理过期。
        返回该分钟的总流量字节数，若无数据则返回 0。
        """
        key = (src_ip, minute_bucket)
        if key in self.bytes_out_current_minute:
            total = self.bytes_out_current_minute.pop(key)
            self.out_series[src_ip].append((minute_bucket * 60.0, total))
            # 清理过期
            self._evict_old(src_ip, _utcnow_ts())
            logger.debug(f"Force flush minute: src={src_ip}, minute_bucket={minute_bucket}, bytes={total}")
            return total
        return 0

    # private ----------------------------------------------------------- #
    def _evict_old(self, ip: str, now_ts: float):
        dq = self.out_series[ip]
        expiry_ts = now_ts - self.window.total_seconds()
        while dq and dq[0][0] < expiry_ts:
            dq.popleft()
        if not dq:
            del self.out_series[ip]


class LateralScanStat:
    """
    内网横向扫描检测

    逻辑：
        - 以 5 min 为窗口；
        - 统计 <dst_ip:dst_port> 去重后的访问数；
        - 超过阈值视为扫描。
    """

    def __init__(self, port_th: int, window_minutes: int):
        self.port_th = port_th
        self.window = timedelta(minutes=window_minutes)
        # {src_ip: deque[(timestamp, (dst_ip, dst_port))]}
        self.conn_series: Dict[str, Deque[Tuple[float, Tuple[str, int]]]] = defaultdict(deque)

    def update_and_check(self, packet_info: Dict[str, Any]) -> bool:
        ts = packet_info.get("timestamp")
        if ts is None:
            now_ts = _utcnow_ts()
        else:
            now_ts = float(ts) if isinstance(ts, (int, float)) else datetime.fromisoformat(ts).timestamp()

        src_ip, dst_ip = packet_info.get("src_ip"), packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        if not (src_ip and dst_ip and dst_port):
            return False


        pair = (dst_ip, int(dst_port))
        # 去重：若已在窗口中则跳过
        if any(existing_pair == pair for _, existing_pair in self.conn_series[src_ip]):
            logger.debug(f"Duplicate lateral connection skipped: src={src_ip}, pair={pair}")
            return False

        self.conn_series[src_ip].append((now_ts, pair))
        logger.debug(f"Lateral connection added: src={src_ip}, pair={pair}")
        # 清理过期
        self._evict_old(src_ip, now_ts)

        unique_pairs: Set[Tuple[str, int]] = {pair for _, pair in self.conn_series[src_ip]}
        return len(unique_pairs) >= self.port_th

    # private ----------------------------------------------------------- #
    def _evict_old(self, ip: str, now_ts: float):
        dq = self.conn_series[ip]
        expiry_ts = now_ts - self.window.total_seconds()
        while dq and dq[0][0] < expiry_ts:
            dq.popleft()
        if not dq:
            del self.conn_series[ip]
        logger.debug(f"Lateral window evicted: src={ip}, remaining={len(dq)}")


# --------------------------------------------------------------------------- #
# ⬇⬇⬇                 3. 主检测器                                            #
# --------------------------------------------------------------------------- #
class InfiltrationDetector:
    """
    渗透攻击检测器

    Parameters
    ----------
    config : dict
        来自 attack_config.yaml 的子树 `config["infiltration"]`
    """

    ATTACK_TYPE = "Infiltration"

    def __init__(self, config: Dict[str, Any]):
        # 读取配置
        self.weights: Dict[str, float] = config.get("score_weights", {
            "rare_domain": 0.3,
            "abnormal_transfer": 0.4,
            "lateral_scan": 0.3,
        })
        # 归一化阈值：如果配置值 >1，按百分比处理，否则按小数处理
        raw_alert = config.get("alert_threshold", 75)
        raw_alert = float(raw_alert)
        self.alert_threshold = raw_alert / 100.0 if raw_alert > 1.0 else raw_alert

        raw_suspected = config.get("suspected_threshold")
        if raw_suspected is not None:
            raw_suspected = float(raw_suspected)
            self.suspected_threshold = raw_suspected / 100.0 if raw_suspected > 1.0 else raw_suspected
        else:
            self.suspected_threshold = self.alert_threshold * 0.6

        self.rare_domain_detector = RareDomainTracker(
            entropy_th=max(float(config.get("rare_domain_entropy", 4.0)), 3.2),  # 提高信息熵判定阈值
            window_minutes=int(config.get("rare_domain_window_minutes", 1440)),
        )
        self.transfer_detector = AbnormalTransferStat(
            z_th=float(config.get("abnormal_transfer_z", 3.5)),  # 提高 z-score 判断标准
            window_minutes=30,
        )
        self.scan_detector = LateralScanStat(
            port_th=int(config.get("lateral_scan_port_threshold", 80)),  # 提高横向扫描端口种类
            window_minutes=int(config.get("lateral_scan_window_minutes", 5)),
        )
        # 横向扫描端口阈值
        self.lateral_scan_port_threshold = int(config.get("lateral_scan_port_threshold", 80))
        # 配置冷却时间和最小 flags 数
        self.cooldown_seconds = int(config.get("cooldown_seconds", 2))
        self.min_flags_required = int(config.get("min_flags_required", 2))
        # 存储近期已触发的特征，按 src_ip 聚合，窗口 5 分钟
        self._flag_history: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "flags": [],
            "first_ts": None,
            "last_alert_ts": 0.0
        })
        self._history_window = 300  # 秒

    # ------------------------------------------------------------------ #
    # public interface：供 detection_manager 调用                        #
    # ------------------------------------------------------------------ #
    def detect(self, packet_info: Dict[str, Any]) -> Tuple[Any, Any, Any]:
        """
        在单包粒度上更新统计器并返回三元组。
        """
        now_ts = packet_info.get("timestamp") or time.time()
        # Parse timestamp string or convert to float
        if isinstance(now_ts, str):
            try:
                # ISO 格式转时间戳
                now_ts = datetime.fromisoformat(now_ts).timestamp()
            except ValueError:
                now_ts = float(now_ts)
        else:
            now_ts = float(now_ts)

        src_ip = packet_info.get("src_ip") or "unknown"

        new_flags = set()

        if self.rare_domain_detector.update_and_check(packet_info):
            new_flags.add("rare_domain")
        if "rare_domain" in new_flags:
            logger.debug(f"稀有域名触发: src={src_ip}")

        if self.transfer_detector.update_and_check(packet_info):
            new_flags.add("abnormal_transfer")
        if "abnormal_transfer" in new_flags:
            logger.debug(f"异常流量比例触发: src={src_ip}")

        if self.scan_detector.update_and_check(packet_info):
            new_flags.add("lateral_scan")
            # 立即确认横向扫描：计算组合标志与归一化得分
            unique_flags = set(new_flags)
            raw_score = sum(self.weights.get(flag, 0.0) for flag in unique_flags)
            normalized_score = raw_score / len(self.weights) if self.weights else 0.0
            extra_info = {
                'src': src_ip,
                'flags': list(unique_flags),
                'score': normalized_score
            }
            logger.warning(
                f"横向扫描检测确认: src={src_ip}, flags={unique_flags}, score={normalized_score:.2f}"
            )
            hist = self._flag_history[src_ip]
            hist["flags"] = []
            hist["first_ts"] = None
            hist["last_alert_ts"] = now_ts
            return True, extra_info, self.ATTACK_TYPE

        # 将本包触发的 flag 累积到历史
        hist = self._flag_history[src_ip]
        if hist["first_ts"] is None:
            hist["first_ts"] = now_ts
        # 清理超时历史
        if now_ts - hist["first_ts"] > self._history_window:
            hist["flags"] = []
            hist["first_ts"] = now_ts

        # 冷却期跳过逻辑
        last_alert = hist.get("last_alert_ts", 0.0)
        if now_ts - last_alert < self.cooldown_seconds:
            return False, None, None  # 冷却期内不重复告警

        hist["flags"].extend(new_flags)

        # 更严格：仅触发一个 flag 不判定为攻击，必须组合触发
        if len(hist["flags"]) < self.min_flags_required:
            return False, None, None

        # 计算综合得分并归一化
        unique_flags = set(hist["flags"])
        raw_score = sum(self.weights.get(flag, 0.0) for flag in unique_flags)
        normalized_score = raw_score / len(self.weights) if self.weights else 0.0
        extra_info = {
            'src': src_ip,
            'flags': list(unique_flags),
            'score': normalized_score
        }

        # 新触发才报警，避免重复
        if new_flags:
            if normalized_score >= self.alert_threshold:
                logger.warning(f"渗透攻击确认: src={src_ip}, flags={list(new_flags)}, score={normalized_score:.2f}")
                hist["flags"] = []
                hist["first_ts"] = None
                hist["last_alert_ts"] = now_ts
                return True, extra_info, self.ATTACK_TYPE
            elif normalized_score >= self.suspected_threshold:
                logger.info(f"渗透攻击疑似: src={src_ip}, flags={list(new_flags)}, score={normalized_score:.2f}")
                hist["flags"] = []
                hist["first_ts"] = None
                hist["last_alert_ts"] = now_ts
                return "suspected", extra_info, self.ATTACK_TYPE

        # 未达到新阈值，视为正常
        return False, None, None

    # ------------------------------------------------------------------ #
    # detection_manager 可在循环或定时任务中调用此方法进行内存回收          #
    # ------------------------------------------------------------------ #
    def evict_expired(self):
        """仅封装，内部各子模块已有自清理逻辑，可按需扩展。"""
        pass


# --------------------------------------------------------------------------- #
# ⬇⬇⬇                 4. 与 detection_manager 的兼容层                         #
# --------------------------------------------------------------------------- #
_detector: InfiltrationDetector | None = None
# 记录子模块状态对象（用于手动清理）
_bloom_filter = None
_outbound_tracker = None
_scan_tracker = None


def init_config(cfg: Dict[str, Any]) -> None:
    global _detector
    # 对传入值进行类型转换
    typed = {}
    for k, v in cfg.items():
        if k in ("alert_threshold", "suspected_threshold"):
            raw = float(v)
            typed[k] = raw/100.0 if raw > 1.0 else raw
        elif isinstance(v, str) and v.isdigit():
            typed[k] = int(v)
        else:
            try:
                typed[k] = float(v)
            except:
                typed[k] = v

    # 如果没有检测器，则创建新的
    if _detector is None:
        _detector = InfiltrationDetector(typed)
        return

    # 否则，清除状态并仅更新指定字段
    clear_state()
    for k, v in typed.items():
        if k == "rare_domain_entropy":
            _detector.rare_domain_detector.entropy_th = v
        elif k == "rare_domain_window_minutes":
            _detector.rare_domain_detector.window = timedelta(minutes=int(v))
        elif k == "abnormal_transfer_z":
            _detector.transfer_detector.z_th = v
        elif k == "lateral_scan_port_threshold":
            _detector.lateral_scan_port_threshold = int(v)
            _detector.scan_detector.port_th = int(v)
        elif k == "lateral_scan_window_minutes":
            _detector.scan_detector.window = timedelta(minutes=int(v))
        elif k == "score_weights":
            _detector.weights = v
        elif k == "alert_threshold":
            _detector.alert_threshold = v
        elif k == "suspected_threshold":
            _detector.suspected_threshold = v
        elif k == "min_flags_required":
            _detector.min_flags_required = int(v)
        elif k == "cooldown_seconds":
            _detector.cooldown_seconds = int(v)


def detect_infiltration(packet_info: Dict[str, Any]):
    """
    detection_manager 每收到一条 packet_info 调用：
        result = detect_infiltration(packet_info)
    """
    if _detector is None:
        # 未初始化时，视为正常流量，返回默认三元组
        return False, None, None
    status, extra_info, typ = _detector.detect(packet_info)
    return status, extra_info, typ


# --------------------------------------------------------------------------- #
# ⬇⬇⬇                 5. 状态清理函数                                         #
# --------------------------------------------------------------------------- #
def clear_state():
    """
    手动清除内部状态，避免多次启停检测时状态残留。
    """
    global _detector, _bloom_filter, _outbound_tracker, _scan_tracker
    if _detector:
        # 重置历史记录
        _detector._flag_history.clear()
        # 清理子组件状态
        _detector.scan_detector.conn_series.clear()
        _detector.transfer_detector.out_series.clear()
        _detector.transfer_detector.bytes_out_current_minute.clear()
        _detector.rare_domain_detector.last_seen.clear()
        # 重新创建子组件以清除其状态
        _bloom_filter = None
        _outbound_tracker = None
        _scan_tracker = None
        # 不要将 _detector 设置为 None；仅清除其状态