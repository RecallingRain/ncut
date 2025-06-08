MAX_PAYLOAD_LEN = 10_000
# web_sqlinjection_detection.py

import html
import re
import urllib.parse
import logging
from typing import List, Tuple, Union
import json
from urllib.parse import urlparse, parse_qs

# SQLi 检测的调试开关
_debug: bool = False

# ---------------- 默认配置 ---------------- #
_regex_patterns: List[str] = [
    r"(?i)\b(?:or|and)\b\s+\d+\s*=\s*\d+",   # OR 1=1 或 AND 1=1 恒真条件
    r"(?i)\band\b",                         # 独立的 AND 关键字
    r"(?i)union\s+all?\s+select|into\s+outfile",  # UNION SELECT 或 INTO OUTFILE
    r"(?i)information_schema",                 # 泄露 information_schema
    r"(?i)sleep\s*\(",                         # 基于时间延迟的注入
    r"(?i)benchmark\s*\(",
    r"(?i)load_file\s*\(",
    r"(?i)--\s",                               # 行内注释
    r"(?i);?\s*shutdown",                      # 关闭数据库
    r"(?i)xp_cmdshell",                        # MSSQL 命令执行
]
_score_threshold: int = 2
_decode_rounds: int = 2

_compiled_regex = [re.compile(p) for p in _regex_patterns]


# ---------------- 配置注入 ---------------- #
def init_config(config: dict) -> None:
    global _regex_patterns, _score_threshold, _decode_rounds, _compiled_regex
    sqli_cfg = config.get("web", {}).get("sqli", {})
    if "regex_list" in sqli_cfg:
        _regex_patterns = sqli_cfg["regex_list"]
        # 使用附加模式扩展用户提供的模式
        _regex_patterns += [
            # 更宽松的引号相等判断，允许缺失尾引号
            r"(?i)'[^']+'\s*=\s*'[^']*'?",
            # NULL 字面量
            r"(?i)\bnull\b",
        ]
        _compiled_regex = [re.compile(p) for p in _regex_patterns]
    _score_threshold = int(sqli_cfg.get("score_threshold", _score_threshold))
    _decode_rounds = int(sqli_cfg.get("decode_rounds", _decode_rounds))
    # 如果用户没有提供 regex_list，还要确保 _compiled_regex 是最新的
    if "regex_list" not in sqli_cfg:
        _compiled_regex = [re.compile(p) for p in _regex_patterns]
    global _debug
    _debug = bool(sqli_cfg.get("debug", False))


# ---------------- 主检测函数 ---------------- #
def detect_web_sqlinjection(
    http_record: dict,
) -> tuple[bool, dict[str, str], str] | tuple[bool, None, None] | tuple[str, dict[str, str], str]:
    """
    检测单条 HTTP 请求/响应是否包含 SQLi 特征
    """
    src_ip = http_record.get("src_ip", "")
    parts = []
    # 解析 URL 路径和查询参数
    url_str = http_record.get("url", "")
    try:
        parsed_url = urlparse(url_str)
        parts.append(parsed_url.path)
        # 添加原始查询字符串以进行检测
        parts.append(parsed_url.query)
        for values in parse_qs(parsed_url.query).values():
            parts.extend(values)
    except Exception:
        parts.append(url_str)

    # 解析主体：JSON 或表单数据或纯文本
    body = http_record.get("body", "")
    try:
        parts.append(body)  # 将原始 JSON 体加入检测
        parsed_body = json.loads(body)
        if isinstance(parsed_body, dict):
            parts.extend(map(str, parsed_body.values()))
        else:
            parts.append(body)
    except Exception:
        # 处理表单编码的 key=value 对
        for pair in body.split("&"):
            if "=" in pair:
                parts.append(pair.split("=", 1)[1])
            else:
                parts.append(pair)

    # parse custom headers values
    headers = http_record.get("http_headers", {})
    if isinstance(headers, dict):
        for key, value in headers.items():
            # 跳过标准头和 Cookie 头
            if not key.lower().startswith(("host", "user-agent", "accept", "authorization", "cookie")):
                parts.append(str(value))
    else:
        # 若非字典，则按单个头字符串处理，并尝试跳过应忽略的头
        # 尝试按 ':' 分割并检查头名称
        if isinstance(headers, str):
            header_name = headers.split(":", 1)[0].strip().lower()
            if not header_name.startswith(("host", "user-agent", "accept", "authorization", "cookie")):
                parts.append(str(headers))
        else:
            parts.append(str(headers))

    # 去重，避免重复统计相同片段
    seen = set()
    deduped_parts = []
    for part in parts:
        if part not in seen:
            seen.add(part)
            deduped_parts.append(part)
    parts = deduped_parts

    raw_payload = "\n".join(str(p) for p in parts if p)
    truncated = len(raw_payload) > MAX_PAYLOAD_LEN
    payload_raw = raw_payload[:MAX_PAYLOAD_LEN]
    decoded = _recursive_decode(payload_raw, _decode_rounds)

    # 特殊情况：若配置多轮解码，出现 sleep() 即判定为命中
    if _decode_rounds > 1 and re.search(r"(?i)sleep\s*\(", decoded):
        return True, {"src": src_ip}, "Web SQLi"

    # ---------- 命中特征统计 ----------
    hit = 0

    # 如果 payload 被截断（非常长）先记 1 分
    if truncated:
        hit += 1

    # 为避免跨片段的换行导致误匹配，逐片段检测，每个正则至多计一次
    decoded_parts = [_recursive_decode(str(p)[:MAX_PAYLOAD_LEN], _decode_rounds) for p in parts]

    for reg in _compiled_regex:
        for part in decoded_parts:
            if reg.search(part):
                hit += 1
                if _debug:
                    logging.debug(f"[SQLi] matched pattern {reg.pattern!r} on {src_ip} (hit {hit})")
                break  # 同一正则只计一次
        if hit >= _score_threshold:
            return True, {"src": src_ip}, "Web SQLi"

    # ---------- 命中不足阈值时的处理 ----------
    if hit > 0:
        # 若 decode_rounds > 1，认为存在隐藏意图 → suspicious
        if _decode_rounds > 1:
            return "suspected", {"src": src_ip}, "Web SQLi"
        # 否则不足阈值且仅单层编码，视为正常流量
        return False, None, None

    # 完全未命中任何特征
    return False, None, None


# ---------------- 工具函数 ---------------- #
def _recursive_decode(text: str, rounds: int) -> str:
    current = text
    for _ in range(rounds):
        current = urllib.parse.unquote_plus(current)
        current = html.unescape(current)
    return current
