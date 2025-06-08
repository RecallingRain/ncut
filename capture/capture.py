# capture.py：流量抓包与持久化模块
# 提供实时抓包、会话管理、批量写入以及文件分割等功能
import os
import sys
import time
import datetime
import pandas as pd
import csv
import json
import logging
import threading
from typing import Optional
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from scapy.all import Raw, AsyncSniffer
from scapy.layers.inet import IP, TCP
from scapy.sessions import TCPSession
from scapy.packet import Packet

# 导入依赖库：系统、并发、日志、数据处理与 Scapy

try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    HTTPRequest = None
    HTTPResponse = None
from scapy.utils import wrpcap

_last_pkt_time = None   # 用于计算 inter_arrival

# 会话上下文类：跟踪单个 TCP 会话的状态与统计信息
class Session:
    def __init__(self, key):
        self.key = key
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.packet_count = 0
        self.byte_count = 0
        self.recent_pkts = []


# 会话管理器：维护所有会话，更新统计并定期清理超时会话
class SessionManager:
    def __init__(self, timeout=300, max_recent=50):
        self.sessions = {}
        self.timeout = timeout
        self.max_recent = max_recent

    def get_session(self, info):
        key = info.get('session_key')
        now = time.time()
        sess = self.sessions.get(key)
        if not sess:
            sess = Session(key)
            self.sessions[key] = sess
        sess.last_seen = now
        sess.packet_count += 1
        sess.byte_count += info['packet_length']
        sess.recent_pkts.append(info)
        if len(sess.recent_pkts) > self.max_recent:
            sess.recent_pkts.pop(0)
        return sess

    def cleanup(self):
        now = time.time()
        for k, sess in list(self.sessions.items()):
            if now - sess.last_seen > self.timeout:
                del self.sessions[k]

# 全局配置：文件目录、日志目录、阈值与列定义等
CAPTURE_DIR = "capture_file"
os.makedirs(CAPTURE_DIR, exist_ok=True)

# 日志配置
LOG_DIR = os.path.join(CAPTURE_DIR, "log")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "capture.log")

logger = logging.getLogger("capture")
logger.setLevel(logging.INFO)
file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8"
)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# 批量写入阈值与文件分割配置
BATCH_SIZE = 100
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# CSV 列定义
CSV_COLUMNS = [
    'timestamp','src_ip','dst_ip','src_port','dst_port','protocol',
    'packet_length','len','inter_arrival',
    'tcp_flags','payload_raw',
    'method','url','http_status','http_headers','http_body',
    'attack_type','is_tls_heartbeat','is_login_failure','is_ssh_handshake_failure',
    'session_key','sess_pkt_count','sess_byte_count'
]

# 全局状态
records_list = []
packets_list = []
lock = threading.Lock()
default_suffix = None
file_index = 0
session_mgr = SessionManager(timeout=300, max_recent=50)

# === 运行控制 ===
_sniffer: Optional[AsyncSniffer] = None          # AsyncSniffer 实例
_executor: Optional[ThreadPoolExecutor] = None   # 线程池实例
_stop_event = threading.Event()                 # 用于优雅停止定时任务

# 自定义 TCP 会话重组：合并分段的数据载荷为完整包
class MyTCPSession(TCPSession):
    @classmethod
    def tcp_reassemble(cls, data: bytes, metadata: dict, session: dict) -> Optional[Packet]:
        # data: 累积的完整 TCP payload
        # metadata 包含 'src', 'dst', 'sport', 'dport', 'proto'
        # 当数据超过一定阈值或流结束时，输出重组包
        if not data:
            return None
        # 始终输出完整 payload，无截断风险
        pkt = Raw(load=data)
        pkt.session_meta = metadata
        pkt.session_state = session
        return pkt

# 提取数据包信息函数：解析包字段，构建统一的字典结构
def extract_packet_info(packet):
    ts = getattr(packet, 'time', time.time())
    global _last_pkt_time
    inter_arrival = ts - _last_pkt_time if _last_pkt_time is not None else 0.0
    _last_pkt_time = ts
    # 统一高精度时间戳为 ISO 格式字符串
    # 如果是浮点数（epoch），则转换为 datetime
    try:
        dt = datetime.datetime.fromtimestamp(ts)
        timestamp_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    except Exception:
        # 已经是字符串或其他，直接转字符串
        timestamp_str = str(ts)
    info = {
        'timestamp': timestamp_str,
        'src_ip': None, 'dst_ip': None,
        'src_port': None, 'dst_port': None,
        'protocol': None,
        'packet_length': len(packet),
        'len': len(packet),
        'inter_arrival': inter_arrival,
        'tcp_flags': None,
        'payload_raw': '',
        'method': None, 'url': None,
        'http_status': None, 'http_headers': None, 'http_body': None,
        'attack_type': 'Normal',
        'is_tls_heartbeat': False,
        'is_login_failure': False,
        'is_ssh_handshake_failure': False,
        'payload_raw_bytes': b'',
        'session_key': None
    }
    try:
        if IP in packet:
            info.update({
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'protocol_num': packet[IP].proto
            })
        if TCP in packet:
            info.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'tcp_flags': str(packet[TCP].flags)
            })
            # 标准化 protocol 字段为字符串，便于后续处理
            info['protocol'] = 'TCP'
        # 对于重组后的 Raw 包，包含 session_meta
        if hasattr(packet, 'session_meta') and isinstance(packet, Raw) and not packet.haslayer(IP):
            meta = packet.session_meta
            info.update({
                'src_ip': meta['src'],
                'dst_ip': meta['dst'],
                'src_port': meta['sport'],
                'dst_port': meta['dport'],
                'protocol': meta['proto'],
                'payload_raw_bytes': packet.load,
                'payload_raw': packet.load.hex()
            })
            # 确保协议字符串化
            info['protocol'] = 'TCP'
        elif Raw in packet:
            data = bytes(packet[Raw].load)
            # 手动解析 HTTP 请求（GET/POST），填充 url 和 http_status
            try:
                text = data.decode('utf-8', errors='ignore')
                if info['dst_port'] in (80, 8000) and (text.startswith('GET') or text.startswith('POST')):
                    lines = text.split('\r\n')
                    parts = lines[0].split(' ')
                    if len(parts) >= 2:
                        info['method'] = parts[0]
                        path = parts[1]
                        host = ''
                        for line in lines[1:]:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                break
                        info['url'] = f"http://{host}{path}" if host else path
                    # 假设请求成功返回 200
                    info['http_status'] = 200
                    sep = text.find('\r\n\r\n')
                    if sep != -1:
                        info['http_body'] = text[sep+4:]
            except Exception:
                pass
            # 截断长度可根据 MTU 调整，但不再依赖此载荷做完整检测
            info['payload_raw_bytes'] = data[:2048]
            info['payload_raw'] = data[:2048].hex()
            if len(data)>=6 and data[0]==0x18 and data[1:3] in (b'\x03\x02',b'\x03\x03') and data[5]==1:
                info['is_tls_heartbeat'] = True
            if info['dst_port']==21 and b'530' in data:
                info['is_login_failure'] = True
            if info['dst_port']==22 and 'R' in info['tcp_flags']:
                info['is_ssh_handshake_failure'] = True
        if HTTPRequest and HTTPRequest in packet:
            req = packet[HTTPRequest]
            info['method'] = req.Method.decode(errors='ignore') if req.Method else None
            path = req.Path.decode(errors='ignore') if req.Path else ''
            host = req.Host.decode(errors='ignore') if req.Host else ''
            info['url'] = f"http://{host}{path}" if host else path
            fields = {k:(v.decode(errors='ignore') if isinstance(v,bytes) else v)
                      for k,v in req.fields.items()}
            info['http_headers'] = json.dumps(fields,ensure_ascii=False)
            if Raw in packet:
                info['http_body'] = packet[Raw].load[:2048].decode(errors='replace')
        elif HTTPResponse and HTTPResponse in packet:
            res = packet[HTTPResponse]
            info['http_status'] = int(res.Status_Code.decode()) if res.Status_Code else None
            fields = {k:(v.decode(errors='ignore') if isinstance(v,bytes) else v)
                      for k,v in res.fields.items()}
            info['http_headers'] = json.dumps(fields,ensure_ascii=False)
            info['http_body'] = packet[Raw].load[:2048].decode(errors='replace') if Raw in packet else None
    except Exception as e:
        logger.exception(f"提取数据包信息出错：{e}")
    # 会话 key
    if info['src_ip'] and info['dst_ip'] and info['src_port'] and info['dst_port']:
        info['session_key'] = (
            f"{info['src_ip']}:{info['src_port']}->"
            f"{info['dst_ip']}:{info['dst_port']}/{info['protocol']}"
        )
    for k,v in info.items():
        if isinstance(v,str): info[k] = v.replace('\n',' ').replace('\r',' ')
    # 如果 protocol 仍为数字，将其转换为字符串
    if isinstance(info.get('protocol'), int):
        info['protocol'] = str(info['protocol'])
    # 通用失败标志，用于 PortScan 检测
    # 确定failure_flag：将登录失败、SSH握手失败、RST或单独的SYN视为失败
    flags = info.get('tcp_flags', '')
    info['failure_flag'] = (
        info.get('is_login_failure', False)
        or info.get('is_ssh_handshake_failure', False)
        or ('R' in flags)
        or ('S' in flags and 'A' not in flags)
    )
    return info

# 批量写入函数（无锁）：将缓存的记录和包写入 CSV 与 PCAP，并处理文件分割
def _save_batch_nolock():
    global records_list,packets_list,default_suffix,file_index
    try:
        now_suffix = datetime.datetime.now().strftime("%Y%m%d_%H")
        if now_suffix!= default_suffix:
            default_suffix=now_suffix
            file_index=0
        hour_dir=os.path.join(CAPTURE_DIR,default_suffix); os.makedirs(hour_dir,exist_ok=True)
        base=f"traffic_{file_index}"
        csv_path=os.path.join(hour_dir,f"{base}.csv")
        pcap_path=os.path.join(hour_dir,f"{base}.pcap")
        if os.path.exists(csv_path) and os.path.getsize(csv_path)> MAX_FILE_SIZE:
            file_index+=1; base=f"traffic_{file_index}"
            csv_path=os.path.join(hour_dir,f"{base}.csv"); pcap_path=os.path.join(hour_dir,f"{base}.pcap")
        df=pd.DataFrame(records_list)
        if 'payload_raw_bytes' in df: df=df.drop(columns=['payload_raw_bytes'])
        df=df[CSV_COLUMNS]
        df.to_csv(csv_path,mode='a' if os.path.exists(csv_path) else 'w',index=False,
                  header=not os.path.exists(csv_path),quoting=csv.QUOTE_ALL)
        logger.info(f"已写入 {len(records_list)} 条记录 到 {csv_path}")
        wrpcap(pcap_path,packets_list,append=os.path.exists(pcap_path))
        logger.info(f"已追加 {len(packets_list)} 个数据包 到 {pcap_path}")
        records_list=[]; packets_list=[]
    except Exception as e:
        logger.exception(f"批量写入失败，正在清空缓存：{e}")
        records_list=[]; packets_list=[]

# 处理单个捕获包函数：提取信息、更新会话、写入缓存并触发批量写入
def handle_packet(packet, packet_handler):
    print("📥 捕获到一个数据包")
    info=extract_packet_info(packet)
    sess=session_mgr.get_session(info)
    info['sess_pkt_count']=sess.packet_count; info['sess_byte_count']=sess.byte_count
    if packet_handler:
        print("📡 准备调用 packet_handler进行自定义处理")
        try: packet_handler(info)
        except Exception as e:
            logger.exception(f"packet_handler 调用出错：{e}")
    with lock:
        records_list.append(info); packets_list.append(packet)
        if len(records_list)>=BATCH_SIZE: _save_batch_nolock()

# 同步保存当前缓存：手动触发批量写入
def save_batch():
    with lock:
        if records_list or packets_list: _save_batch_nolock()

# 定时任务函数：周期性执行保存和会话清理
def _periodic_tasks():
    if _stop_event.is_set():
        return
    save_batch()
    session_mgr.cleanup()
    threading.Timer(60, _periodic_tasks).start()


# 启动抓包函数：启动 AsyncSniffer、线程池与定时任务，可选择阻塞模式，默认阻塞直到 `stop_capture()` 被调用；设置 block=False 可让调用方自行控制主循环。
def start_capture(interface=None, packet_handler=None, max_workers=4, block=True):

    global _sniffer, _executor, _stop_event
    _stop_event.clear()  #解决重复启停后定时任务未重启的问题
    _periodic_tasks()
    logger.info(f"开始在接口 {interface} 上进行流量捕获")

    # 如果未指定特定接口，则捕获所有接口流量
    iface = None if not interface else interface

    # 线程池负责解析 / 持久化
    _executor = ThreadPoolExecutor(max_workers=max_workers)

    # 使用 AsyncSniffer 以便后续显式停止
    _sniffer = AsyncSniffer(
        iface=iface,
        prn=lambda pkt: (_executor.submit(handle_packet, pkt, packet_handler), None)[1],
        store=False,
        session=MyTCPSession,
    )
    _sniffer.start()

    if block:
        try:
            _sniffer.join()  # 阻塞直到 stop_capture()
        except KeyboardInterrupt:
            logger.info("检测到 Ctrl+C 中断，停止抓包服务")
            stop_capture()

# 停止抓包函数：停止 sniffer、关闭线程池、写入剩余数据并清理任务，在main中调用
def stop_capture():

    global _sniffer, _executor
    _stop_event.set()  # 通知定时任务不再继续

    if _sniffer is not None:
        logger.info("正在停止抓包服务…")
        try:
            _sniffer.stop()
            _sniffer.join()
        finally:
            _sniffer = None

    if _executor is not None:
        _executor.shutdown(wait=True)
        _executor = None

    save_batch()
    logger.info("抓包已完成并保存所有数据")


#检查sudo权限
def check_sudo():
    if hasattr(os,'geteuid') and os.geteuid()!=0:
        logger.warning("尝试使用 sudo 提权")
        try: os.execvp("sudo",["sudo",sys.executable]+sys.argv)
        except Exception as e: logger.exception("Elevation failed: %s",e); sys.exit(1)
    else:
        logger.info("非 UNIX 平台，跳过 sudo 权限检查")


if __name__ == "__main__":
    check_sudo()
    try:
        start_capture(interface="lo0")
    except KeyboardInterrupt:
        stop_capture()
