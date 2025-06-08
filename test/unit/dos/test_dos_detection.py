# test/unit/dos/test_dos_detection.py

import time
import pytest
from detection.dos.dos_detection import (
    detect_dos_hulk,
    detect_dos_goldeneye,
    detect_dos_slowloris,
    detect_dos_slowhttptest,
    detect_dos_attacks,
    load_config,
    clear_state,
    CONFIG,
    global_tracker,
    hulk_window,
    goldeneye_window,
    slowloris_window,
    slowhttp_window,
    get_dynamic_threshold
)

@pytest.fixture(autouse=True)
def reset_all():
    """
    每个测试前清空所有滑动窗口状态
    """
    clear_state()
    yield
    clear_state()

def simulate_packets(fn, base_ip, base_ts, count, **pkt_kwargs):
    """
    调用单个检测函数 fn，重复发送 count 个包，返回结果列表。
    每个包时间间隔 0.1s。
    """
    results = []
    for i in range(count):
        pkt = dict(pkt_kwargs)
        pkt['src_ip'] = base_ip
        pkt['timestamp'] = base_ts + i * 0.1
        res = fn(pkt)
        results.append(res)
    return results

def test_dos_hulk_detection():
    """测试 DoS Hulk：超过 hulk_threshold 触发疑似/确认"""
    print("\n=== DoS Hulk 测试开始 ===")
    base_ts = time.time()
    results = []
    for idx in range(CONFIG['hulk_threshold'] + 1):
        pkt = {'src_ip': '10.0.0.1', 'timestamp': base_ts, 'protocol_num': 6, 'dst_port': 80}
        res = detect_dos_hulk(pkt)
        print(f"[Hulk] 第{idx+1}次请求 -> {res}")
        results.append(res)
    assert all(r[0] is False for r in results[:CONFIG['hulk_threshold']])
    assert results[-1][0] is True and results[-1][2] == 'DoS Hulk'
    print(f"<<< 测试结果: test_dos_hulk_detection 结束，最终输出 = {results[-1]} >>>")

def test_dos_goldeneye_detection():
    """测试 DoS GoldenEye：在 goldeneye_time_window 内发送超过阈值连开"""
    print("\n=== DoS GoldenEye 测试开始 ===")
    base_ts = time.time()
    results = []
    for idx in range(CONFIG['goldeneye_request_threshold'] + 1):
        pkt = {'src_ip': '10.0.0.2', 'timestamp': base_ts, 'protocol_num': 6, 'dst_port': 443}
        res = detect_dos_goldeneye(pkt)
        print(f"[GoldenEye] 第{idx+1}次连接 -> {res}")
        results.append(res)
    assert results[-1][0] is True and results[-1][2] == 'DoS GoldenEye'
    print(f"<<< 测试结果: test_dos_goldeneye_detection 结束，最终输出 = {results[-1]} >>>")

def test_dos_slowloris_detection():
    """测试 DoS Slowloris：纯 SYN 包超过阈值"""
    print("\n=== Slowloris 测试: 纯 SYN 包 ===")
    base_ts = time.time()
    threshold = CONFIG['slowloris_syn_threshold']
    # 先发 threshold 次 SYN 包
    ok = simulate_packets(
        detect_dos_slowloris,
        "10.0.0.3",
        base_ts,
        threshold,
        protocol_num=6,
        dst_port=80,
        flags='S'
    )
    for idx, r in enumerate(ok, start=1):
        print(f"[Slowloris] 第{idx}次 SYN -> {r}")
    assert all(r[0] is False for r in ok), "前 threshold 次应为正常"
    print("再发一次 SYN，进行确认检测")
    # 再发一包，应确认
    res = detect_dos_slowloris({
        'src_ip': "10.0.0.3",
        'timestamp': base_ts + threshold * 0.1,
        'protocol_num': 6,
        'dst_port': 80,
        'flags': 'S'
    })
    print(f"[Slowloris] 确认检测结果 -> {res}")
    assert res[0] is True and res[2] == 'DoS Slowloris'
    print(f"<<< 测试结果: test_dos_slowloris_detection 结束，最终输出 = {res} >>>")

def test_dos_slowhttptest_detection():
    """测试 DoS Slowhttptest：小包数量超过阈值"""
    print("\n=== Slowhttptest 测试: 小包数量超过阈值 ===")
    base_ts = time.time()
    threshold = CONFIG['slowhttp_count_threshold']
    # 发 threshold 次小包 (< packet_size_threshold)
    ok = simulate_packets(
        detect_dos_slowhttptest,
        "10.0.0.4",
        base_ts,
        threshold,
        protocol_num=6,
        dst_port=80,
        packet_length=CONFIG['slowhttp_packet_size_threshold'] - 1
    )
    for idx, r in enumerate(ok, start=1):
        print(f"[Slowhttptest] 第{idx}次小包 -> {r}")
    assert all(r[0] is False for r in ok), "前 threshold 次应为正常"
    print("再发一次小包，进行确认检测")
    # 再发一包，应确认
    res = detect_dos_slowhttptest({
        'src_ip': "10.0.0.4",
        'timestamp': base_ts + threshold * 0.1,
        'protocol_num': 6,
        'dst_port': 80,
        'packet_length': CONFIG['slowhttp_packet_size_threshold'] - 1
    })
    print(f"[Slowhttptest] 确认检测结果 -> {res}")
    assert res[0] is True and res[2] == 'DoS Slowhttptest'
    print(f"<<< 测试结果: test_dos_slowhttptest_detection 结束，最终输出 = {res} >>>")

def test_dynamic_threshold_effect():
    """测试动态阈值：增加全局流量后 dyn 上升"""
    print("\n=== 动态阈值效果测试 ===")
    # 模拟 global_tracker 里有大量其他流量
    now = time.time()
    for i in range(50):
        global_tracker.append(now + i * 0.01)
    base = CONFIG['hulk_threshold']
    print(f"全局流量 count={global_tracker.count()}, dyn_divisor={CONFIG['dyn_divisor']}, dyn={get_dynamic_threshold(base)}")
    # 此时 dyn = max(base, total/CONFIG['dyn_divisor'])
    expected = max(base, int(global_tracker.count() / CONFIG['dyn_divisor']))
    assert get_dynamic_threshold(base) == expected
    print(f"<<< 测试结果: test_dynamic_threshold_effect 结束，最终输出 dyn={get_dynamic_threshold(base)} >>>")

def test_load_config_updates_window():
    """测试 load_config 自动更新所有窗口尺寸"""
    print("\n=== load_config 更新窗口尺寸测试 ===")
    # 原始值
    old = CONFIG['slowloris_conn_window']
    new_size = old + 10
    load_config({'slowloris_conn_window': new_size})
    print(f"旧窗口尺寸: {old}, 新窗口尺寸: {new_size}, slowloris_window.window_size: {slowloris_window.window_size}")
    # 窗口实例应同步更新
    assert slowloris_window.window_size == new_size
    print(f"<<< 测试结果: test_load_config_updates_window 结束，窗口尺寸={slowloris_window.window_size} >>>")

def test_detect_dos_attacks_precedence():
    """测试多种检测同时满足时，按顺序返回第一个检测结果"""
    print("\n=== 多种检测优先级测试 ===")
    base_ts = time.time()
    for i in range(CONFIG['hulk_threshold'] + 1):
        res = detect_dos_hulk({'src_ip': '10.0.0.5', 'timestamp': base_ts, 'protocol_num': 6, 'dst_port': 80})
        print(f"detect_dos_hulk 第{i+1}次调用结果: {res}")
    res = detect_dos_attacks({'src_ip': '10.0.0.5', 'timestamp': base_ts, 'protocol_num': 6, 'dst_port': 80})
    print(f"detect_dos_attacks 结果: {res}")
    assert res and res[2] == 'DoS Hulk'
    print(f"<<< 测试结果: test_detect_dos_attacks_precedence 结束，最终输出 = {res} >>>")

def test_clear_state_effect():
    """测试 clear_state 确实重置窗口计数"""
    print("\n=== clear_state 重置测试 ===")
    now = time.time()
    # 先让 hulk_window 里有记录
    detect_dos_hulk({'src_ip':'10.0.0.6','timestamp':now,'protocol_num':6,'dst_port':80})
    before_count = hulk_window.count()
    print(f"清理前 hulk_window 计数: {before_count}")
    # 清理状态
    clear_state()
    after_count = hulk_window.count()
    print(f"清理后 hulk_window 计数: {after_count}")
    assert before_count == 1
    assert after_count == 0
    print(f"<<< 测试结果: test_clear_state_effect 结束，before={before_count}, after={after_count} >>>")

def test_threshold_boundary_counts():
    """边界值测试：静态阈值和动态阈值临界点"""
    print("\n=== 边界值测试: 静态阈值和动态阈值临界点 ===")
    base = CONFIG['hulk_threshold']
    total = 0
    # no global traffic, dyn == base
    # count == base -> normal
    for i in range(base):
        res = detect_dos_hulk({'src_ip':'10.1.1.1','timestamp': time.time(), 'protocol_num':6,'dst_port':80})
        print(f"第{i+1}个包检测结果: {res}")
    assert res[0] is False
    # one more -> confirmed
    res2 = detect_dos_hulk({'src_ip':'10.1.1.1','timestamp': time.time(), 'protocol_num':6,'dst_port':80})
    print(f"超过阈值第{base+1}个包检测结果: {res2}")
    assert res2[0] is True
    print(f"<<< 测试结果: test_threshold_boundary_counts 结束，边界前={res}, 边界后={res2} >>>")

def test_dynamic_threshold_increase():
    """动态阈值提高后，低频流量视为正常"""
    print("\n=== 动态阈值提高测试 ===")
    # 增加全局流量，使 dyn >> base
    now = time.time()
    needed = (CONFIG['hulk_threshold'] + 1) * CONFIG['dyn_divisor']
    for i in range(needed):
        global_tracker.append(now)
    base = CONFIG['hulk_threshold']
    dyn = get_dynamic_threshold(base)
    print(f"基础阈值: {base}, 动态阈值: {dyn}")
    assert dyn > base
    # send base+1 packets -> should be suspected, not confirmed (低于动态阈值)
    results = []
    for i in range(base+1):
        res = detect_dos_hulk({'src_ip':'10.1.1.2','timestamp': now, 'protocol_num':6,'dst_port':80})
        print(f"第{i+1}个包检测结果: {res}")
        results.append(res)
    last = results[-1]
    print(f"最后一个包结果: {last}")
    assert last[0] == "suspected"
    print(f"<<< 测试结果: test_dynamic_threshold_increase 结束，dyn={dyn}, 最后一次={last} >>>")

def test_sliding_window_expiry():
    """滑动窗口过期后重计数"""
    print("\n=== 滑动窗口过期测试 ===")
    now = time.time()
    # send 3 packets
    for i in range(3):
        res = detect_dos_hulk({'src_ip':'10.1.1.3','timestamp': now + i, 'protocol_num':6,'dst_port':80})
        print(f"第{i+1}个包检测结果: {res}")
    # after window_size seconds, old packets expire
    future = now + CONFIG['hulk_time_window'] + 1
    res = detect_dos_hulk({'src_ip':'10.1.1.3','timestamp': future, 'protocol_num':6,'dst_port':80})
    print(f"过期后新包检测结果: {res}")
    # count is 1 -> normal
    assert res[0] is False
    print(f"<<< 测试结果: test_sliding_window_expiry 结束，最终输出 = {res} >>>")

def test_mixed_protocol_ports():
    """多协议/端口组合测试"""
    print("\n=== 多协议/端口组合测试 ===")
    now = time.time()
    # Hulk on 80
    for i in range(CONFIG['hulk_threshold'] + 1):
        res = detect_dos_hulk({'src_ip':'10.1.1.4','timestamp': now ,'protocol_num':6,'dst_port':80})
        print(f"Hulk 第{i+1}个包检测结果: {res}")
    # GoldenEye on 443
    for i in range(CONFIG['goldeneye_request_threshold'] + 1):
        res = detect_dos_goldeneye({'src_ip':'10.1.1.4','timestamp': now ,'protocol_num':6,'dst_port':443})
        print(f"GoldenEye 第{i+1}个包检测结果: {res}")
    # unified should pick Hulk first
    res = detect_dos_attacks({'src_ip':'10.1.1.4','timestamp': now ,'protocol_num':6,'dst_port':80})
    print(f"综合检测结果: {res}")
    assert res[2] == 'DoS Hulk'
    print(f"<<< 测试结果: test_mixed_protocol_ports 结束，最终输出 = {res} >>>")

def test_non_tcp_traffic():
    """非 TCP 流量不检测"""
    print("\n=== 非 TCP 流量测试 ===")
    now = time.time()
    # ICMP and UDP
    for proto in [1, 17]:
        for i in range(100):
            res = detect_dos_hulk({'src_ip':'10.1.1.5','timestamp': now,'protocol_num': proto,'dst_port':80})
            print(f"协议 {proto} 第{i+1}个包检测结果: {res}")
            assert res == (False, None, None)
    # 按协议检查结束，无输出
    print("<<< 测试结果: test_non_tcp_traffic 结束，所有协议未触发检测 >>>")

def test_runtime_config_change():
    """运行时修改配置立即生效"""
    print("\n=== 运行时配置修改测试 ===")
    now = time.time()
    load_config({'hulk_threshold': 2})
    # send 3 -> confirmed
    for i in range(3):
        res = detect_dos_hulk({'src_ip':'10.1.1.6','timestamp': now + i*0.01,'protocol_num':6,'dst_port':80})
        print(f"第{i+1}个包检测结果: {res}")
    assert res[0] is True
    print(f"<<< 测试结果: test_runtime_config_change 结束，最终输出 = {res} >>>")

def test_logging_output(caplog):
    """日志输出测试：疑似和确认均有 log"""
    print("\n=== 日志输出测试 ===")
    caplog.set_level('INFO')
    now = time.time()
    # suspected
    results = []
    for i in range(CONFIG['hulk_threshold'] + 1):
        res = detect_dos_hulk({'src_ip':'10.1.1.7','timestamp': now ,'protocol_num':6,'dst_port':80})
        print(f"第{i+1}个包检测结果: {res}")
        results.append(res)
    print(f"日志内容:\n{caplog.text}")
    assert "DoS Hulk suspected attack" in caplog.text or "DoS Hulk confirmed attack" in caplog.text
    print(f"<<< 测试结果: test_logging_output 结束，日志内容:\n{caplog.text} >>>")

def test_invalid_input():
    """非法输入安全返回"""
    print("\n=== 非法输入测试 ===")
    # missing fields
    res = detect_dos_hulk({'src_ip':'10.1.1.8'})
    print(f"非法输入检测结果: {res}")
    assert res == (False, None, None)
    print(f"<<< 测试结果: test_invalid_input 结束，最终输出 = {res} >>>")

def test_concurrent_threads():
    """并发测试，多线程下无竞态"""
    print("\n=== 并发多线程测试 ===")
    import threading
    now = time.time()
    def task(ip):
        for i in range(CONFIG['hulk_threshold'] + 1):
            res = detect_dos_hulk({'src_ip':ip,'timestamp': now ,'protocol_num':6,'dst_port':80})
            print(f"线程 {ip} 第{i+1}个包检测结果: {res}")
    threads = [threading.Thread(target=task, args=(f'10.1.1.{i}',)) for i in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    # verify each window
    for i in range(10):
        try:
            count = hulk_window.count(ip=f'10.1.1.{i}')
            print(f"IP 10.1.1.{i} 计数: {count}")
            assert count >= CONFIG['hulk_threshold']+1
        except TypeError:
            # If count does not accept ip, just check total count >= threshold
            total = hulk_window.count()
            print(f"总计数: {total}")
            assert total >= CONFIG['hulk_threshold']+1
    # 并发测试结束
    print("<<< 测试结果: test_concurrent_threads 结束，多线程统计正常 >>>")

def test_normal_low_rate_hulk():
    """低速 TCP 流正常不报（低于 Hulk 阈值）"""
    print("\n=== 低速 TCP 流正常测试 ===")
    now = time.time()
    # 发送少于 Hulk 阈值的包，且间隔大于 time_window
    for i in range(CONFIG['hulk_threshold'] - 1):
        res = detect_dos_hulk({
            'src_ip': '10.2.2.1',
            'timestamp': now + i * (CONFIG['hulk_time_window'] + 1),
            'protocol_num': 6,
            'dst_port': 80
        })
        print(f"第{i+1}个包检测结果: {res}")
        assert res == (False, None, None)
    # 结束
    print("<<< 测试结果: test_normal_low_rate_hulk 结束，低速 TCP 不触发检测 >>>")

def test_normal_goldeneye_slow_rate():
    """GoldenEye 慢速连接正常不报（超出 time window）"""
    print("\n=== GoldenEye 慢速连接测试 ===")
    now = time.time()
    threshold = CONFIG['goldeneye_request_threshold']
    interval = CONFIG['goldeneye_time_window'] + 1
    for i in range(threshold + 1):
        res = detect_dos_goldeneye({
            'src_ip': '10.2.2.2',
            'timestamp': now + i * interval,
            'protocol_num': 6,
            'dst_port': 443
        })
        print(f"第{i+1}次连接检测结果: {res}")
        assert res == (False, None, None)
    # 结束
    print("<<< 测试结果: test_normal_goldeneye_slow_rate 结束，慢速 GoldenEye 不触发检测 >>>")

def test_normal_http_mixed_traffic():
    """混合端口 TCP 流正常不报"""
    print("\n=== 混合端口 TCP 流正常测试 ===")
    now = time.time()
    # 在不同端口并且分散时间发送
    ports = [80, 443, 8080, 8000]
    for idx, port in enumerate(ports * (CONFIG['hulk_threshold'] // len(ports) + 1)):
        res = detect_dos_hulk({
            'src_ip': '10.2.2.3',
            'timestamp': now + idx * (CONFIG['hulk_time_window'] + 1),
            'protocol_num': 6,
            'dst_port': port
        })
        print(f"第{idx+1}个包端口{port}检测结果: {res}")
        assert res == (False, None, None)
    # 结束
    print("<<< 测试结果: test_normal_http_mixed_traffic 结束，混合端口 TCP 不触发检测 >>>")