# web_xss_detection.py


import html
import re
import urllib.parse
from typing import List, Tuple, Union
from html.parser import HTMLParser
import logging

# Optional debug logging for XSS detection
_xss_debug = False
# ---------------- 配置（默认值） ---------------- #

# 解码保护限制
_MAX_DECODE_ROUNDS = 5           # 最大解码轮数上限
_MAX_PAYLOAD_LENGTH = 10000      # 超过此长度则停止递归解码

 # ---------------- 默认正则 + 可扩展 ---------------- #
_DEFAULT_REGEX_PATTERNS: List[str] = [
    r"(?i)(<script[^>]*>|<iframe[^>]*>)",
    r"(?i)on[a-z]+\s*=\s*['\"]?",
    r"(?i)(src|href)\s*=\s*['\"]?javascript:",
    r"(?i)eval\s*\(",
    r"(?i)document\.cookie",
]
_regex_patterns: List[str] = _DEFAULT_REGEX_PATTERNS.copy()
_score_threshold: int = 2          # 命中多少条正则算“确定攻击”
_decode_rounds: int = 2            # 递归解码轮数

# 预编译正则
_compiled_regex = [re.compile(p) for p in _regex_patterns]


# ---------------- 辅助类 ---------------- #
class ContextAwareParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.suspected_fragments = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self.in_script = True
        # also record the raw start-tag text for attribute-based patterns
        raw_tag = self.get_starttag_text()
        if raw_tag:
            ctx = "script" if self.in_script else "text"
            self.suspected_fragments.append((ctx, raw_tag))


    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.in_script = False

    def handle_data(self, data):
        context = "script" if self.in_script else "text"
        self.suspected_fragments.append((context, data))


def init_config(config: dict) -> None:
    """
    由 detection_manager 注入 YAML 配置
    """
    global _regex_patterns, _score_threshold, _decode_rounds, _compiled_regex
    xss_cfg = config.get("web", {}).get("xss", {})
    if "regex_list" in xss_cfg:
        custom = xss_cfg["regex_list"]
        # 先放自定义，再追加默认中未出现的，保持顺序 & 去重
        merged = custom + [p for p in _DEFAULT_REGEX_PATTERNS if p not in custom]
        _regex_patterns.clear()
        _regex_patterns.extend(merged)
        _compiled_regex[:] = [re.compile(p) for p in _regex_patterns]
    _score_threshold = int(xss_cfg.get("score_threshold", _score_threshold))
    _decode_rounds = int(xss_cfg.get("decode_rounds", _decode_rounds))
    # 限制解码轮数不超过上限
    if _decode_rounds > _MAX_DECODE_ROUNDS:
        _decode_rounds = _MAX_DECODE_ROUNDS
    # Optional debug flag
    global _xss_debug
    _xss_debug = bool(xss_cfg.get("debug", False))
    if _xss_debug:
        logging.basicConfig(level=logging.DEBUG)


# ---------------- 主检测函数 ---------------- #
def detect_web_xss(http_record: dict) -> tuple[bool, None, None] | tuple[bool, dict[str, str], str] | tuple[
    str, dict[str, str], str]:
    """
    检测是否存在 XSS 攻击
    仅检查单条请求/响应，不维护窗口
    """
    src_ip = http_record.get("src_ip", "")
    # 合并检测面：URL、Body、Headers
    parts = [
        http_record.get("url", ""),
        http_record.get("body", ""),
    ]
    headers = http_record.get("http_headers")
    if headers:
        parts.append(headers)

    payload_raw = "\n".join(str(p) for p in parts if p)

    # 递归解码（URL → HTML）以应对双重编码
    decoded = _recursive_decode(payload_raw, _decode_rounds)
    # Fast path: skip expensive regex checks when unlikely to contain XSS
    lower_decoded = decoded.lower()
    has_closing_script = "</script>" in lower_decoded
    has_closing_iframe = "</iframe>" in lower_decoded
    if '<' not in decoded and 'javascript:' not in lower_decoded:
        return False, None, None

    # 使用 ContextAwareParser 分析上下文
    parser = ContextAwareParser()
    parser.feed(decoded)

    # 统计命中
    hit = 0
    for context, fragment in parser.suspected_fragments:
        # 跳过纯粹的 <script> / <iframe> 开始标签 ——
        # 1) 出现在普通文本上下文，或
        # 2) 整个 payload 没有对应的闭合标签（说明只是字面文本）
        frag_l = fragment.lower().strip()
        if frag_l in ("<script>", "<iframe>"):
            if context == "text" or (frag_l == "<script>" and not has_closing_script) or (frag_l == "<iframe>" and not has_closing_iframe):
                continue

        for reg in _compiled_regex:
            # always apply all patterns to every fragment
            if reg.search(fragment):
                if _xss_debug:
                    logging.debug(f"XSS debug: matched pattern '{reg.pattern}' in context '{context}' fragment: {fragment[:50]!r}")
                hit += 1
                # do not break; allow all regexes to match for each fragment
                # threshold comparison: require strictly greater than threshold
                if hit >= _score_threshold:
                    if _xss_debug:
                        logging.debug(f"XSS debug: total hits {hit}, threshold {_score_threshold}")
                    return True, {"src": src_ip}, "Web XSS"

    # 边界：命中但未达阈值
    if _xss_debug and hit:
        logging.debug(f"XSS debug: suspected hit count {hit} below threshold {_score_threshold}")
    if hit:
        return "suspected", {"src": src_ip}, "Web XSS"

    return False, None, None


# ---------------- 工具函数 ---------------- #
def _recursive_decode(text: str, rounds: int) -> str:
    """
    对字符串做 URL 解码 + HTML 实体反解码，多轮递归
    """
    # clamp to configured maximum rounds
    rounds = min(rounds, _MAX_DECODE_ROUNDS)
    current = text
    for _ in range(rounds):
        # 如果 payload 太长，停止递归解码
        if len(current) > _MAX_PAYLOAD_LENGTH:
            break
        current = urllib.parse.unquote_plus(current)
        current = html.unescape(current)
    return current
