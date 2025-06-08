import importlib
# detection/detection_manager.py

# 全局场景变量及加载标志
_config_loaded = False
_selected_scenario = None

import os
import yaml
import threading
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio, time



main_event_loop = asyncio.get_event_loop()


# 冷却/去重：记录最近广播时间，避免同一IP+类型重复广播
_last_broadcast_time_dm: dict[str, float] = {}
COOLDOWN_INTERVAL = 60  # 秒

# —— 各检测模块导入 ——
from detection.dos.dos_detection import (
    detect_dos_attacks, load_config as load_dos_cfg
)
from detection.ddos.ddos_detection import (
    detect_ddos_attacks, load_config as load_ddos_cfg
)
from detection.dos.heartbleed_detection import (
    detect_heartbleed_attacks, load_config as load_heartbleed_cfg
)
from detection.bruteforce.bruteforce_detection import (
    detect_ftp_patator, detect_ssh_patator, load_config as load_bruteforce_cfg
)
from detection.web_attack.web_bruteforce_detection import (
    detect_web_bruteforce, init_config as load_web_bruteforce_cfg
)
from detection.web_attack.web_xss_detection import (
    detect_web_xss, init_config as load_web_xss_cfg
)
from detection.web_attack.web_sqlinjection_detection import (
    detect_web_sqlinjection, init_config as load_web_sqli_cfg
)
from detection.infiltration.infiltration_detection import (
    detect_infiltration, init_config as load_infiltration_cfg
)
from detection.botnet.botnet_ares_detection import (
    detect_botnet_ares, init_config as load_botnet_ares_cfg
)
from detection.portscan.portscan_detection import (
    detect_portscan, init_config as load_portscan_cfg
)


# —— 日志配置 ——
logger = logging.getLogger("detection_manager")
logger.setLevel(logging.INFO)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)
    fh = logging.FileHandler("detection_manager.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)




# —— 1. 注册检测模块 ——
# 列表中定义所有可用检测模块及其加载配置函数、默认顺序
MODULES = [
    {"name": "PortScan",       "func": detect_portscan,         "load_cfg": load_portscan_cfg,     "cfg_key": "portscan_detection",     "order": 1},
    {"name": "FTP-Patator",    "func": detect_ftp_patator,      "load_cfg": load_bruteforce_cfg,   "cfg_key": "bruteforce_detection",   "order": 2},
    {"name": "SSH-Patator",    "func": detect_ssh_patator,      "load_cfg": load_bruteforce_cfg,   "cfg_key": "bruteforce_detection",   "order": 3},
    {"name": "Web-Bruteforce", "func": detect_web_bruteforce,   "load_cfg": load_web_bruteforce_cfg,"cfg_key": "web_attack_detection",  "order": 4},
    {"name": "Web-XSS",        "func": detect_web_xss,          "load_cfg": load_web_xss_cfg,      "cfg_key": "web_attack_detection",   "order": 5},
    {"name": "Web-SQLi",       "func": detect_web_sqlinjection, "load_cfg": load_web_sqli_cfg,     "cfg_key": "web_attack_detection",   "order": 6},
    {"name": "Heartbleed",     "func": detect_heartbleed_attacks,"load_cfg": load_heartbleed_cfg,  "cfg_key": "heartbleed_detection",   "order": 7},
    {"name": "DoS",            "func": detect_dos_attacks,      "load_cfg": load_dos_cfg,          "cfg_key": "dos_detection",          "order": 8},
    {"name": "DDoS",           "func": detect_ddos_attacks,     "load_cfg": load_ddos_cfg,         "cfg_key": "ddos_detection",         "order": 9},
    {"name": "Infiltration",   "func": detect_infiltration,     "load_cfg": load_infiltration_cfg, "cfg_key": "infiltration_detection", "order": 10},
    {"name": "Botnet-Ares",    "func": detect_botnet_ares,      "load_cfg": load_botnet_ares_cfg,  "cfg_key": "botnet_ares_detection",  "order": 11},

]

# —— 1.1 协议分流表 ——
_HTTP_MODULES = {"Web-Bruteforce", "Web-XSS", "Web-SQLi"}
_SSH_MODULES  = {"SSH-Patator"}
_FTP_MODULES  = {"FTP-Patator"}
# 其余模块默认对所有流量开放

def _select_modules(packet_info):
    """
    根据 packet_info 的协议特征返回需要调用的检测模块子集，
    以减少无关模块的误报与开销。
    """
    logger.info("开始模块筛选，packet_info: %s", {k: packet_info.get(k) for k in ['protocol', 'src_port', 'dst_port', 'url']})
    proto = (packet_info.get("protocol") or "").upper()
    sport = packet_info.get("src_port")
    dport = packet_info.get("dst_port")

    selected = []
    for m in MODULES:
        n = m["name"]
        if n in _HTTP_MODULES:
            # 简易判断：URL 字段或 protocol=HTTP
            if packet_info.get("url") or proto == "HTTP":
                selected.append(m)
        elif n in _SSH_MODULES:
            if 22 in (sport, dport):
                selected.append(m)
        elif n in _FTP_MODULES:
            if 21 in (sport, dport):
                selected.append(m)
        else:
            selected.append(m)   # 通用模块
    logger.info("📦 当前数据包协议：%s | 源端口：%s | 目标端口：%s", proto, sport, dport)
    logger.info("✅ 启用检测模块：%s", [m["name"] for m in selected])
    logger.info("模块筛选结果详情: %s", selected)
    return selected

# —— 2. 自适应排序统计 ——
# 根据一段时间内各模块的命中率自动调整顺序
class StatsManager:
    def __init__(self, interval=60):
        self.interval = interval
        self._lock = threading.Lock()
        self._reset()
        threading.Timer(self.interval, self._adjust).start()

    def _reset(self):
        # 初始化各模块调用与命中统计
        self.calls = {m["name"]: 0 for m in MODULES}
        self.hits  = {m["name"]: 0 for m in MODULES}

    def record(self, module_name, hit=False):
        # 记录一次调用与是否命中
        with self._lock:
            self.calls[module_name] += 1
            if hit:
                self.hits[module_name] += 1

    def _adjust(self):
        # 周期性调整顺序，按命中率高低排序
        with self._lock:
            rates = {
                name: (self.hits[name] / self.calls[name]) if self.calls[name] else 0
                for name in self.calls
            }
            logger.info("计算模块命中率: %s", rates)
            MODULES.sort(key=lambda m: rates.get(m["name"], 0), reverse=True)
            self._reset()
        threading.Timer(self.interval, self._adjust).start()

stats = StatsManager()

# —— 3. 全局调用与命中计数器 & 周期报表 ——
detection_counter = Counter()   # 模块调用次数
attack_counter    = Counter()   # 攻击类型命中次数

def _report(interval=300):
    # 定期打印统计信息
    logger.info("=== Detection Summary === calls=%s hits=%s",
                dict(detection_counter), dict(attack_counter))
    logger.debug("调用统计详情: calls=%s hits=%s", dict(detection_counter), dict(attack_counter))
    threading.Timer(interval, _report, args=(interval,)).start()
_report()


def load_attack_config(config_path: str, scenario: str = None) -> None:
    """
    读取 attack_config.yaml，分发模块配置，并可静态覆盖顺序
    """
    logger.info(f"load_attack_config called with scenario argument: {scenario}")
    global _config_loaded, _selected_scenario
    logger.info("开始加载配置: %s", config_path)
    if scenario:
        _selected_scenario = scenario
    if not os.path.exists(config_path):
        logger.warning("配置文件未找到：%s", config_path)
        return
    with open(config_path, 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f) or {}

    scene_name = _selected_scenario or cfg.get('default_scenario','development')
    logger.info(f"Determined scene_name in detection_manager: {scene_name}")
    scene = cfg.get('scenarios', {}).get(scene_name, {})
    logger.info("加载场景配置: %s", scene)

    # 分发每个模块的私有配置
    for m in MODULES:
        try:
            sub = scene.get(m["cfg_key"], {})
            m["load_cfg"](sub)
            logger.info("模块%s配置已应用: %s", m["name"], sub)
        except Exception as e:
            logger.error("模块%s加载配置失败：%s", m["name"], e, exc_info=True)

    # 静态顺序覆盖（attack_config.yaml 中 module_settings）
    order_map = {}
    for s in scene.get('module_settings', []):
        try:
            order_map[s['name']] = int(s['order'])
        except Exception:
            logger.warning("非法 order:%r for module %r", s.get('order'), s.get('name'))
    for m in MODULES:
        if m["name"] in order_map:
            m["order"] = order_map[m["name"]]
    MODULES.sort(key=lambda x: x["order"])
    logger.info("检测模块加载顺序：%s", [m["name"] for m in MODULES])
    logger.info("配置加载完成，场景: %s", scene_name)
    _config_loaded = True


def _invoke_module(m, packet_info):
    """
    调用单个模块，统一异常捕获与返回格式：
    (module_name, status, attacker_ip, attack_type)
    """
    name = m["name"]
    logger.debug("调用模块 %s 开始", name)
    try:
        res = m["func"](packet_info)
        logger.debug("调用模块 %s 返回: %s", name, res)
        # print(f"📣 模块 {name} 返回检测结果：", res)
        logger.debug("模块%s 返回检测结果：%s", name, res)
    except Exception as e:
        logger.error("模块%s异常：%s", name, e, exc_info=True)
        stats.record(name, hit=False)  # ✅ 异常也算一次调用
        return False, None, None

    if not res or not isinstance(res, (list, tuple)):
        return False, None, None

    flag = res[0]
    if flag not in (True, "suspected"):
        return False, None, None
    # True, "suspected"等直接作为状态返回
    ip = res[1] if len(res) > 1 else None
    typ = res[2] if len(res) > 2 else None
    if isinstance(ip, str):
        ip = {"src": ip}

    return flag, ip, typ


def run_detection(packet_info, collect_all: bool = False):
    """
    并行调用所有模块：
    - collect_all=False: 抢占首个 CONFIRMED/SUSPECTED 即返回
    - collect_all=True : 等待所有完成，收集所有非 NORMAL 的结果
    返回值：
      * collect_all=False -> (flag, ip, typ)
      * collect_all=True  -> list of (flag, ip, typ)
    """
    if not _config_loaded:
        logger.error("配置未加载，请先通过 /config/scenario 接口设置场景并加载配置")
        return False, None, None
    logger.info("开始执行 run_detection, collect_all=%s", collect_all)
    # 基于协议特征筛选本次需要调用的模块
    active_modules = _select_modules(packet_info)
    logger.info("选中模块名单: %s", [m["name"] for m in active_modules])

    # 记录调用开始
    for m in active_modules:
        detection_counter[m["name"]] += 1
        stats.record(m["name"], hit=False)

    results = []
    with ThreadPoolExecutor(max_workers=len(active_modules)) as exe:
        futures = {exe.submit(_invoke_module, m, packet_info): m for m in active_modules}

        if not collect_all:
            # 抢占模式
            for fut in as_completed(futures):
                status, ip, typ = fut.result()
                if status not in (True, "suspected"):
                    continue
                # 冷却检查，避免重复广播
                now = time.time()
                key = f"{ip}-{typ}"
                if key not in _last_broadcast_time_dm or now - _last_broadcast_time_dm[key] >= COOLDOWN_INTERVAL:
                    _last_broadcast_time_dm[key] = now
                    # 广播检测告警
                    mod_name = futures[fut]["name"]
                    stats.record(mod_name, hit=True)
                    attack_counter[typ] += 1
                    # 区分日志级别
                    if status is True:
                        logger.info("模块%s CONFIRMED: %s src=%s", mod_name, typ, ip)
                    else:
                        logger.warning("模块%s SUSPECTED: %s src=%s", mod_name, typ, ip)
                else:
                    logger.debug("detection_manager: skip duplicate alert for %s", key)
                # 取消其余
                for other in futures:
                    if other is not fut:
                        other.cancel()
                # 返回 (flag, ip, typ)
                logger.info("run_detection 返回: (%s, %s, %s)", status, ip, typ)
                return status, ip, typ
            # 全部NORMAL
            logger.debug("run_detection: all NORMAL")
            logger.info("run_detection 返回: (False, None, None)")
            return False, None, None
        else:
            # 收集所有命中
            for fut in as_completed(futures):
                status, ip, typ = fut.result()
                if status not in (True, "suspected"):
                    continue
                mod_name = futures[fut]["name"]
                stats.record(mod_name, hit=True)
                attack_counter[typ] += 1
                if status == True:
                    logger.info("模块%s CONFIRMED: %s src=%s", mod_name, typ, ip)
                elif status == "suspected":
                    logger.warning("模块%s SUSPECTED: %s src=%s", mod_name, typ, ip)
                else:
                    logger.warning("模块%s SUSPECTED: %s src=%s", mod_name, typ, ip)
                results.append((status, ip, typ))
            if not results:
                logger.debug("run_detection(collect_all): all NORMAL")
            logger.info("run_detection 返回: %s", results)
            return results



def clear_all_states():
    """
    清除所有检测模块的内部状态（如滑窗、历史记录等）。
    """
    logger.info("开始清理所有模块状态")
    for m in MODULES:
        if m["name"] == "ML-Kitsune":  # 保留 KitNET 训练状态，勿清空
            continue
        module_name = m["func"].__module__
        logger.debug("清理模块状态: %s", module_name)
        try:
            mod = importlib.import_module(module_name)
            if hasattr(mod, "clear_state"):
                mod.clear_state()
                logger.debug("模块%s状态已清理完成", module_name)
        except ImportError:
            continue
    logger.info("状态清理完成")

# —— 定期清理所有检测模块状态 —— 每60秒执行一次 ——
def _schedule_clear(interval: int = 60):
    logger.info("定时状态清理触发，间隔: %s秒", interval)
    clear_all_states()
    logger.info("定时状态清理完成")
    threading.Timer(interval, _schedule_clear, args=(interval,)).start()

# 启动首次定时清理
_schedule_clear(60)
# End of detection_manager.py
