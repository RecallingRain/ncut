# ws_manager.py：WebSocket 管理模块
# 提供 WebSocket 客户端连接管理、实时告警广播与邮件通知功能
from fastapi.staticfiles import StaticFiles
import yaml
import smtplib
import asyncio
import time
from email.mime.text import MIMEText
from typing import List
from fastapi import WebSocket, WebSocketDisconnect
import json
import logging
from datetime import datetime



logger = logging.getLogger("ws_manager")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("ws_manager.log", encoding="utf-8")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)
import detection.detection_manager as detection_manager


# 加载邮件配置：从 YAML 文件读取并返回邮件发送相关配置
def load_email_config(config_path: str = "email_config.yaml") -> dict:
    """
    从 YAML 文件加载邮件配置
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            cfg = yaml.safe_load(f)
        email_cfg = cfg.get('email', {})
        logger.info(f"邮件配置加载成功: {email_cfg}")
    except Exception as e:
        logger.warning(f"⚠️ 加载邮件配置失败: {e}")
        email_cfg = {}
    return email_cfg


# 邮件发送器类：封装同步与异步邮件发送功能
class EmailSender:
    """简单的邮件发送器"""
    def __init__(self, config: dict) -> None:
        self.enable = config.get('enable', False)
        self.smtp_server = config.get('smtp_server')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username')
        self.password = config.get('password')
        self.from_addr = config.get('from_addr')
        # 是否使用 SSL (例如 465 端口)
        self.use_ssl = config.get('smtp_use_ssl', False)
        # 设置连接超时时间（秒）
        self.timeout = config.get('smtp_timeout', 10)
        self.to_addrs = config.get('to_addrs', [])
        # 只对指定级别及以上发送
        self.level_threshold = config.get('level_threshold', 'warning')

    # 同步发送邮件：根据主题与正文构造并发送邮件
    def _send_sync(self, subject: str, body: str) -> None:
        try:
            msg = MIMEText(body, 'html', 'utf-8')
            msg['Subject'] = subject
            msg['From'] = self.from_addr
            msg['To'] = ", ".join(self.to_addrs)

            # 根据配置选择 SMTP 或 SMTP_SSL
            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port, timeout=self.timeout)
            else:
                smtp = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=self.timeout)
                smtp.starttls()

            with smtp:
                smtp.login(self.username, self.password)
                smtp.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            logger.info(f"✉️ 邮件已发送: {subject}")
        except Exception as e:
            logger.error(f"❌ 邮件发送失败: {e}")

    # 异步发送邮件：在后台线程调用同步发送，并可进行级别过滤
    async def send(self, alert: dict) -> None:
        """
        根据告警信息异步发送邮件
        判断是否启用和级别过滤
        """
        logger.info(f"开始处理告警邮件: {alert}")
        if not self.enable:
            return
        level = alert.get('level', '').lower()
        # 简单级别排序： warning < critical
        levels = {'warning': 1, 'critical': 2}
        if levels.get(level, 0) < levels.get(self.level_threshold, 0):
            return

        # 格式化时间戳
        raw_time = alert.get('time')
        if isinstance(raw_time, (int, float)):
            formatted_time = datetime.fromtimestamp(raw_time).strftime('%Y-%m-%d %H:%M:%S')
        else:
            formatted_time = raw_time

        subject = f"[安全告警][{alert.get('level').upper()}] {alert.get('type')} 来自 {alert.get('detail', {}).get('src')}"
        body = (
            f"<h3>安全告警通知</h3>"
            f"<p><strong>时间：</strong>{formatted_time}</p>"
            f"<p><strong>类型：</strong>{alert.get('type')}</p>"
            f"<p><strong>源 IP：</strong>{alert.get('detail', {}).get('src')}</p>"
            f"<p><strong>级别：</strong>{alert.get('level')}</p>"
            f"<p><strong>链接：</strong><a href='http://localhost:63342/System/frontend/user.html?_ijt=i3jdoami0ohqupso2bdjj2fvus&_ij_reload=RELOAD_ON_SAVE'>点击查看告警界面</a></p>"
        )
        # 在后台线程发送
        await asyncio.to_thread(self._send_sync, subject, body)


# WebSocket 管理器类：管理客户端连接、广播消息并触发邮件通知
class WSManager:
    """简单的 WebSocket 客户端管理器，用于广播实时告警，并发送邮件通知。"""

    def __init__(self) -> None:
        self.active: List[WebSocket] = []
        # 加载邮件配置并初始化发送器
        email_cfg = load_email_config()
        self.email_sender = EmailSender(email_cfg)

    # 处理新客户端连接：接受 WebSocket 并添加到活动列表
    async def connect(self, ws: WebSocket) -> None:
        """新客户端接入并接受连接。"""
        await ws.accept()
        self.active.append(ws)
        logger.info(f"🟢 新客户端连接！当前连接数：{len(self.active)}")

    # 处理客户端断开：从活动列表移除 WebSocket
    def disconnect(self, ws: WebSocket) -> None:
        """客户端断开。"""
        if ws in self.active:
            self.active.remove(ws)
        logger.info(f"🔴 客户端断开！当前连接数：{len(self.active)}")

    # 广播告警消息：向所有活动客户端发送，并异步触发邮件发送
    async def broadcast(self, alert: dict) -> None:
        """
        向所有客户端推送告警消息，并触发邮件通知。
        异常客户端将被移除。
        """
        logger.info(f"📤 广播中... 客户端数：{len(self.active)} | 消息：{alert}")
        message_text = json.dumps(alert)
        # 广播 WebSocket
        for ws in list(self.active):
            try:
                await ws.send_text(message_text)
            except Exception:
                self.disconnect(ws)
        # 异步发送邮件
        await self.email_sender.send(alert)
        logger.info(f"✅ 广播和邮件发送完成: {alert}")


    # 处理数据包：调用检测管理器并根据结果生成告警
    async def process_packet(self, packet_info: dict) -> None:
        """
        调用 detection_manager.run_detection 获取三元组，并根据状态触发告警。
        """
        logger.info(f"处理数据包信息：{packet_info}")
        # 在检测开始时，发送初始邮件告警
        initial_alert = {
            "time": time.time(),
            "timestamp": packet_info.get("timestamp"),
            "type": "DDos",
            "detail": {"src": "172.20.10.1"},
            "level": "critical"
        }
        # 仅发送邮件，不广播前端
        await self.email_sender.send(initial_alert)
        # 从检测管理器获取状态、攻击者IP和攻击类型
        status, attacker_ip, attack_type = detection_manager.run_detection(packet_info)
        logger.info(f"处理数据包检测结果：status={status}, 攻击源IP={attacker_ip}, 攻击类型={attack_type}")
        # 仅在确认攻击(True)或疑似攻击("suspected")时触发告警
        if status is True:
            alert = {
                "time": time.time(),
                "timestamp": packet_info.get("timestamp"),
                "type": attack_type,
                "detail": {"src": attacker_ip},
                "level": "critical"
            }
            await self.broadcast(alert)
        elif str(status).lower() == "suspected":
            alert = {
                "time": time.time(),
                "timestamp": packet_info.get("timestamp"),
                "type": attack_type,
                "detail": {"src": attacker_ip},
                "level": "warning"
            }
            await self.broadcast(alert)


# # ——— WebSocket 路由：/ws/alerts ———
# @app.websocket("/ws/alerts")
# async def alerts_ws(ws: WebSocket):
#     """
#     前端通过 ws://<host>/ws/alerts 连接后：
#     1. 将 WebSocket 加入 WSManager.active
#     2. 给客户端发一条握手确认消息
#     3. 持续等待心跳/占位消息，以保持连接
#     4. 断开时自动从 active 移除
#     """
#     await ws_manager.connect(ws)
#     try:
#         # 可选：握手成功后发送欢迎信息，便于前端立即验证
#         await ws.send_text(json.dumps({"msg": "WebSocket connected", "time": time.time()}))
#         while True:
#             # 前端可定期发送心跳文本，保持连接
#             await ws.receive_text()
#     except WebSocketDisconnect:
#         pass
#     finally:
#         ws_manager.disconnect(ws)

# 单例，全局导入即可复用
ws_manager = WSManager()










# 测试入口：执行时会广播一个测试告警
if __name__ == "__main__":
    import asyncio
    # 脚本独立运行时，直接发送初始邮件告警
    initial_alert = {
        "time": time.time(),
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "type": "ddos",
        "detail": {"src": "172.20.10.1"},
        "level": "critical"
    }
    logger.info("脚本启动，发送初始邮件告警...")
    asyncio.run(ws_manager.email_sender.send(initial_alert))
    logger.info("初始邮件告警发送完成。")
