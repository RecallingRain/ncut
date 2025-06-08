import time
import pytest
from detection.ddos.ddos_detection import (
    reset_ddos_state,
    load_config,
    detect_ddos
)

# 方便构造 packet_info
def make_pkt(ip):
    return {'src_ip': ip}


@pytest.fixture(autouse=True)
def reset_state_before_each():
    """每个测试前重置全局状态"""
    reset_ddos_state()
    yield
    reset_ddos_state()


def fast_forward(seconds):
    """Monkey-patch time.time 使窗口滚动"""
    base = time.time()
    return base + seconds


def test_normal():
    """
    场景：只有 1 个 IP，包数非常少，平滑后活跃 IP < 5，should be 正常
    """
    load_config({'window_size': 5, 'smoothing_alpha': 0.5})
    print("\n=== 正常流量——单 IP 少量包 ===")
    # 发送 3 个包，时间相同
    for idx in range(3):
        print(f"Step {idx+1}: 发送第 {idx+1} 个包，src_ip=1.1.1.1")
        res = detect_ddos(make_pkt('1.1.1.1'))
        print(f"Step {idx+1}: 检测结果 = {res}")
        assert res is False
    print("测试结果：正常流量测试通过")


def test_suspected():
    """
    场景：活跃 IP 数在动态 suspicious 与 dynamic_high 之间，返回 "suspected"
    """
    load_config({
        'window_size': 5,
        'smoothing_alpha': 0.2,
        'active_ip_suspicious_threshold': 2,
        'active_ip_high_threshold': 10,
        'threshold_suspicious_factor': 1.0,
        'threshold_high_factor': 2.0,
    })
    print("\n=== 疑似攻击——活跃 IP 数进入中间区间 ===")
    # 先打暖机：5 次不同 IP，激活平滑
    for idx in range(10):
        print(f"Warmup Step {idx+1}: 发送暖机包，src_ip=10.0.0.{idx}")
        detect_ddos({'src_ip': f'10.0.0.{idx}'})
    print("正式检测: 发送第 11 个包，src_ip=10.0.0.100")
    res = detect_ddos(make_pkt('10.0.0.100'))
    print(f"正式检测结果: {res}")
    assert res == "suspected"
    print("测试结果：疑似攻击测试通过")


def test_multi_source_ip_flooding_trigger(monkeypatch):
    """
    场景：快速产生大量不同 IP，活跃 IP 数超过 dynamic_high，返回 True
    """
    load_config({
        'window_size': 1,
        'smoothing_alpha': 1.0,  # 立即脱离冷启动
        'active_ip_suspicious_threshold': 0,  # 关闭可疑阈值
        'threshold_suspicious_factor': 0.0,
        'active_ip_high_threshold': 10,
        'threshold_high_factor': 1.0
    })
    import time
    base_time = time.time()
    # 所有包都在同一秒
    monkeypatch.setattr(time, "time", lambda: base_time)
    print("\n== 真正攻击——多源 IP 洪泛 ===")
    r = None
    for idx in range(1001):
        r = detect_ddos({'src_ip': f'192.168.0.{idx}'})
        print(f"Step {idx+1}: 发送包，src_ip=192.168.0.{idx}，检测结果 = {r}")
        if r is True:
            break
    assert r is True
    print("测试结果：多源 IP 洪泛攻击测试通过\n")


def test_single_ip_burst_trigger(monkeypatch):
    """
    场景：单 IP 在窗口内包数超过 per_ip_high_threshold，返回 True
    """
    load_config({
        'window_size': 5,
        'smoothing_alpha': 1.0,  # 立即脱离冷启动
        'active_ip_suspicious_threshold': 0,  # 关闭可疑阈值
        'threshold_suspicious_factor': 0.0,
        'per_ip_high_threshold': 5,
        'active_ip_high_threshold': 1000,
        'threshold_high_factor': 100.0,
    })
    import time
    base_time = time.time()
    monkeypatch.setattr(time, "time", lambda: base_time)
    print("\n=== 真正攻击——单 IP 突发 ===")
    # 发送 100 个包，超过单 IP 阈值
    res = None
    for idx in range(100):
        print(f"Step {idx+1}: 发送第 {idx+1} 个包，src_ip=8.8.8.8")
        res = detect_ddos({'src_ip': '8.8.8.8'})
        print(f"Step {idx+1}: 检测结果 = {res}")
    assert res is True
    print("测试结果：单 IP 突发攻击测试通过\n")


def test_packet_rate_trigger(monkeypatch):
    """
    场景：整体包率超过 pkt_high_threshold，返回 True
    """
    load_config({
        'window_size': 5,
        'pkt_high_threshold': 2,   # 每秒大于 2 包触发
        'per_ip_high_threshold': 1000,
        'active_ip_suspicious_threshold': 0,
        'active_ip_high_threshold': 1000,
        'threshold_suspicious_factor': 0.0,
        'threshold_high_factor': 100.0,
    })
    import time
    base_time = time.time()
    monkeypatch.setattr(time, "time", lambda: base_time)
    print("\n=== 真正攻击——整体包速率过高 ===")
    # 在 1 秒内发送 50 包，速率 = 50/5=10 > 2
    res = None
    for idx in range(50):
        print(f"Step {idx+1}: 发送第 {idx+1} 个包，src_ip=1.2.3.{idx}")
        res = detect_ddos({'src_ip': f'1.2.3.{idx}'})
        print(f"Step {idx+1}: 检测结果 = {res}")
    assert res is True
    print("测试结果：包速率攻击测试通过\n")
