# -*- coding: utf-8 -*-
"""
test_heartbleed_detection.py

针对 Heartbleed 检测模块的单元测试：
- 心跳速率规则检测（detect_heartbleed_rule）
- 离线深度解析检测（deep_heartbleed_analysis）
- 规则 + 深度联合流程（detect_heartbleed_attacks）
"""

import time
import types
import pytest
import shutil
import os
from pyshark.capture.capture import TSharkCrashException

from detection.dos import heartbleed_detection as hb

# ---- 工具函数提前 ----
def gen_hb_pkt(ts: float, src: str = "1.1.1.1") -> dict:
    """构造一个带 TLS Heartbeat 标志的数据包字典"""
    return {
        "timestamp": ts,
        "src_ip": src,
        "dst_port": hb.CONFIG["heartbleed_port"],
        "is_tls_heartbeat": True,
        "packet_length": hb.CONFIG["pkt_size_limit"] + 1,  # 确保载荷大于最小长度
    }

# 自动清理全局状态
@pytest.fixture(autouse=True)
def _reset_hb_state():
    """每个测试执行前清空 Heartbleed 相关状态"""
    hb.clear_state()
    yield
    hb.clear_state()

def test_clear_state_function():
    print("\n=== 测试 清除状态 ===")
    print("首先调用 detect_heartbleed_rule 模拟心跳检测，然后调用 clear_state 清理状态，检查是否正确清空。")
    """测试 clear_state 接口清空 _heartbeat_tracker"""
    # 模拟添加数据
    hb.detect_heartbleed_rule(gen_hb_pkt(time.time()))
    print("检测后, tracker:", hb._heartbeat_tracker)
    assert len(hb._heartbeat_tracker) > 0
    hb.clear_state()
    assert all(len(dq) == 0 for dq in hb._heartbeat_tracker.values())
    print("<<< 测试结果: 状态已被清空，_heartbeat_tracker 为空。")

# —— 1. 速率规则检测 —— #

@pytest.mark.parametrize("cnt,expect", [
    (hb.CONFIG["pkt_threshold"] - 1, False),  # 未超过阈值
    (hb.CONFIG["pkt_threshold"], True),       # 刚好达到阈值
    (hb.CONFIG["pkt_threshold"] + 5, True),   # 超过阈值
])
def test_detect_heartbleed_rule(cnt: int, expect: bool):
    print(f"\n=== 测试 detect_heartbleed_规则: cnt={cnt}, 预期={expect} ===")
    print("对连续 Heartbeat 包计数，并在达到阈值时确认检测。")
    """测试 detect_heartbleed_rule 在不同计数下的行为"""
    start = time.time()
    res = (False, None, None)
    for i in range(cnt):
        pkt = gen_hb_pkt(start + i * 0.1)
        res = hb.detect_heartbleed_rule(pkt)
        print(f"迭代 {i+1}/{cnt}, 包={pkt}, 结果={res}")
    assert res[0] == expect
    print("<<< 测试结果: 当包数达到预期，返回结果符合预期。")

def test_packet_length_threshold():
    print("\n=== 测试 包长度阈值: 小包与大包场景测试 ===")
    print("验证小于阈值长度的包不计数，大于阈值长度的包计数并触发检测。")
    """测试只有大于 pkt_size_limit 的包才计数"""
    hb.clear_state()
    ts = time.time()
    # 小于等于限制
    pkt = gen_hb_pkt(ts)
    pkt['packet_length'] = hb.CONFIG['pkt_size_limit']
    res = hb.detect_heartbleed_rule(pkt)
    print("小包结果:", res)
    assert res[0] is False
    # 大于限制
    pkt['packet_length'] = hb.CONFIG['pkt_size_limit'] + 1
    for idx in range(hb.CONFIG['pkt_threshold'] + 1):
        res = hb.detect_heartbleed_rule(pkt)
        print(f"大包迭代 {idx+1}, 结果={res}")
    assert res[0] is True
    print("<<< 测试结果: 大包达到阈值后成功检测。")

def test_sliding_window_expiry_rule():
    print("\n=== 测试 滑动窗口过期规则 ===")
    print("模拟时间间隔超过滑动窗口后，旧包被清除，重新计数应正常。")
    """测试规则检测滑动窗口过期"""
    hb.clear_state()
    start = time.time()
    for i in range(hb.CONFIG['pkt_threshold']):
        pkt = gen_hb_pkt(start + i*(hb.CONFIG['time_window']+1))
        res = hb.detect_heartbleed_rule(pkt)
        print(f"迭代 {i+1}, 包时间戳已过期, 结果={res}")
        assert res[0] is False
    print("<<< 测试结果: 窗口过期后计数重置，未触发检测。")

# ---- 非 Heartbeat 包不计数且不误报 ----
def test_non_heartbeat_packets():
    print("\n=== 测试 非心跳包不应计数 ===")
    print("非 Heartbeat 标记的包即使长度满足也不应该被计数。")
    """非 Heartbeat 包不计数且不误报"""
    hb.clear_state()
    pkt = gen_hb_pkt(time.time())
    print("包:", pkt)
    pkt['is_tls_heartbeat'] = False
    pkt['packet_length'] = hb.CONFIG['pkt_size_limit'] + 100
    res = hb.detect_heartbleed_rule(pkt)
    print("结果:", res)
    assert res == (False, None, None)
    print("<<< 测试结果: 非心跳包未被计数，未误报。")

# —— 2. 离线深度解析 —— #

def test_deep_heartbleed_analysis(monkeypatch):
    print("\n=== 测试 深度 Heartbleed 解析: 模拟 FileCapture 返回虚拟包列表 ===")
    print("Monkeypatch FileCapture 返回自定义数据包列表，检查 deep_heartbleed_analysis 能正确识别源 IP。")
    """
    monkeypatch Pyshark.FileCapture，模拟捕获到两条符合 Heartbleed 条件的包
    """
    # Dummy packet 模拟结构
    class _DummyPkt:
        def __init__(self, ip):
            self.ip = types.SimpleNamespace(src=ip)
            self.tls = types.SimpleNamespace(layer_name='tls', heartbeat=True)
        def __repr__(self):
            return f"<DummyPkt src={self.ip.src}>"

    dummy_list = [_DummyPkt("9.9.9.9"), _DummyPkt("8.8.8.8")]
    print("虚拟包列表:", dummy_list)

    class _DummyCap(list):
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def close(self):
            pass

    dummy_cap = _DummyCap(dummy_list)

    # 替换 pyshark.FileCapture
    monkeypatch.setattr("pyshark.FileCapture", lambda *args, **kwargs: dummy_cap)

    suspects = hb.deep_heartbleed_analysis("dummy.pcap")
    print("深度解析嫌疑源:", suspects)
    assert set(suspects) == {"9.9.9.9", "8.8.8.8"}
    print("<<< 测试结果: 深度解析正确识别了所有源 IP。")

def test_deep_analysis_timeout(monkeypatch):
    print("\n=== 测试 深度解析超时分支 ===")
    print("配置超时为 0，此分支应立即返回空结果，无异常。")
    """测试 deep_heartbleed_analysis 超时分支"""
    # 模拟 FileCapture 阻塞
    class BlockCap:
        def __iter__(self): return iter([])
        def close(self): pass
    def long_capture(*args, **kwargs):
        import time; time.sleep(0.1); return BlockCap()
    monkeypatch.setattr("pyshark.FileCapture", long_capture)
    # 设置超时为0秒
    monkeypatch.setitem(hb.CONFIG, 'deep_timeout', 0)
    # Should return empty list without exception
    res = hb.deep_heartbleed_analysis("dummy")
    print("结果:", res)
    assert res == []
    print("<<< 测试结果: 超时分支立即返回空结果，无崩溃。")

# ---- TSharkCrashException 分支 ----
def test_deep_analysis_crash(monkeypatch, caplog):
    print("\n=== 测试 深度解析崩溃分支 (TSharkCrashException) ===")
    print("模拟 TSharkCrashException，应返回空列表并记录警告日志。")
    """模拟 TSharkCrashException，deep_heartbleed_analysis 安全返回"""
    def crash_capture(*args, **kwargs):
        raise TSharkCrashException("crash")
    monkeypatch.setattr("pyshark.FileCapture", crash_capture)
    caplog.set_level("WARNING")
    res = hb.deep_heartbleed_analysis("dummy")
    print("结果:", res)
    assert res == []
    assert "Deep heartbleed analysis failed" in caplog.text
    print("<<< 测试结果: 崩溃分支安全返回空列表并记录警告。")

# ---- 临时文件清理分支 ----
def test_tempfile_cleanup(monkeypatch):
    print("\n=== 测试 临时文件清理 ===")
    print("通过 monkeypatch tempfile 和 os.remove，验证临时文件名被正确删除。")
    """验证临时文件被删除"""
    removed = []
    class DummyTmp:
        def __init__(self):
            self.name = "tmp.pcap"
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr("tempfile.NamedTemporaryFile", lambda *args, **kwargs: DummyTmp())
    monkeypatch.setattr("shutil.copy", lambda src, dst: None)
    monkeypatch.setattr("os.remove", lambda p: removed.append(p))
    # make FileCapture yield no packets
    monkeypatch.setattr("pyshark.FileCapture", lambda *args, **kwargs: [])
    print("调用 deep_heartbleed_analysis")
    res = hb.deep_heartbleed_analysis("dummy.pcap")
    print("删除的文件列表:", removed)
    assert removed == ["tmp.pcap"]
    print("<<< 测试结果: 临时文件已被正确删除。")

# —— 3. 规则 + 深度联合流程 —— #

def test_detect_heartbleed_attacks_flow(monkeypatch):
    print("\n=== 测试 detect_heartbleed_attacks 流程: 规则检测后调用深度解析 ===")
    print("当规则检测触发后，会调用 deep_heartbleed_analysis 进行源 IP 确定，并返回字符串形式的 src。")
    """
    在速率规则触发后，再用 deep_heartbleed_analysis 确认攻击源
    """
    # 强制 deep analysis 返回指定 IP
    monkeypatch.setattr(hb, "deep_heartbleed_analysis", lambda pcap: ["2.2.2.2"])
    start = time.time()
    res = (False, None, None)
    # 先触发速率规则
    for i in range(hb.CONFIG["pkt_threshold"] + 1):
        pkt = gen_hb_pkt(start + i * 0.1, src="2.2.2.2")
        res = hb.detect_heartbleed_attacks(pkt)
        print(f"迭代 {i+1}, 结果={res}")
    # 最终应返回 (True, {'src': '2.2.2.2'}, "DoS Heartbleed")
    assert res == (True, {'src': '2.2.2.2'}, "DoS Heartbleed")
    print("<<< 测试结果: 规则 + 深度流程返回正确的源 IP 字符串。")

# # ---- 规则未命中时走深度解析分支 ----
# def test_detect_heartbleed_attacks_fallback(monkeypatch):
#     print("\n=== 测试 detect_heartbleed_attacks 回退分支: 规则未命中时调用深度解析 ===")
#     print("当规则未命中时，通过 deep_heartbleed_analysis 回退，并返回分析得到的 IP。")
#     """规则未命中时走深度解析分支"""
#     hb.clear_state()
#     # rule always false
#     monkeypatch.setattr(hb, "detect_heartbleed_rule", lambda pkt: (False, None, None))
#     monkeypatch.setattr(hb, "deep_heartbleed_analysis", lambda p: ["4.4.4.4"])
#     res = hb.detect_heartbleed_attacks(gen_hb_pkt(time.time()))
#     print("结果:", res)
#     assert res == (True, "4.4.4.4", "DoS Heartbleed")
#     print("<<< 测试结果: 回退分支返回 deep analysis 获取的 IP。")

def test_custom_port():
    print("\n=== 测试 自定义 heartbleed_port 检测 ===")
    print("修改 heartbleed_port 配置后，检测函数应使用新端口。")
    """测试 heartbleed_port 可配置"""
    hb.clear_state()
    # 修改端口
    hb.load_config({'heartbleed_port': 8443})
    print("新端口:", hb.CONFIG['heartbleed_port'])
    pkt = gen_hb_pkt(time.time())
    pkt['dst_port'] = 8443
    for idx in range(hb.CONFIG['pkt_threshold'] + 1):
        res = hb.detect_heartbleed_rule(pkt)
        print(f"迭代 {idx+1}, 结果={res}")
    assert res[0] is True
    print("<<< 测试结果: 自定义端口生效，检测成功。")

# ---- 规则确认时打印 info 日志 ----
def test_rule_logging(caplog):
    print("\n=== 测试 规则确认时日志 INFO 输出 ===")
    print("触发阈值后，日志记录器应打印 Heartbleed rule confirmed 信息。")
    """规则确认时打印 info 日志"""
    caplog.set_level("INFO")
    ts = time.time()
    for _ in range(hb.CONFIG['pkt_threshold'] + 1):
        hb.detect_heartbleed_rule(gen_hb_pkt(ts))
        print(f"调用检测函数，时间戳={ts}")
    assert "Heartbleed rule confirmed" in caplog.text
    print("caplog 内容:", caplog.text)
    print("<<< 测试结果: 日志中包含 Heartbleed rule confirmed 信息。")


def test_detect_heartbleed_attacks_suspected(monkeypatch):
    print("\n=== 测试 detect_heartbleed_attacks 直接返回疑似结果 ===")
    print("当规则返回 'suspected' 时，检测入口应直接返回疑似结果，不调用深度解析。")
    """当规则检测返回疑似时，detect_heartbleed_attacks 应直接返回疑似结果"""
    # 模拟规则检测返回疑似
    monkeypatch.setattr(hb, "detect_heartbleed_rule",
                        lambda pkt: ("suspected", {"src": "5.5.5.5"}, "DoS Heartbleed"))
    # 深度解析不应被调用，返回空也无影响
    monkeypatch.setattr(hb, "deep_heartbleed_analysis", lambda p: [])
    res = hb.detect_heartbleed_attacks(gen_hb_pkt(time.time(), src="5.5.5.5"))
    print("结果:", res)
    assert res == ("suspected", {"src": "5.5.5.5"}, "DoS Heartbleed")
    print("<<< 测试结果: 疑似分支直接返回，不调用深度解析。")