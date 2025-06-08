import threading
import asyncio
import logging



logger = logging.getLogger("main")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("main.log", encoding="utf-8")
fh.setLevel(logging.INFO)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)


_last_broadcast_time = {}
BROADCAST_INTERVAL = 60
main_event_loop = asyncio.get_event_loop()




import capture.capture as capture
import detection.detection_manager as detection_manager
from detection.detection_manager import load_attack_config
import threading
import time
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
import json, os
from auth.auth import verify_password
from detection.ml import ml_pyod
# --- Auth security and dependency ---
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user = payload.get("sub")
        logger.info("get_current_user: token有效 user=%s", user)
        return user
    except JWTError:
        logger.error("get_current_user: 无效Token")
        raise HTTPException(status_code=401, detail="无效Token")
from pathlib import Path

from fastapi import WebSocket
from alert.ws_manager import ws_manager

"""统一处理每一条捕获的数据包"""
def my_packet_handler(packet_info):
    logger.info("my_packet_handler: packet_info=%s", packet_info)
    try:
        status, attacker_ip, attack_type = detection_manager.run_detection(packet_info)
        logger.info(f"✅ 检测状态识别：status={status} | type={type(status)}")
        logger.info(f"🧪 检测模块返回状态：{status} | 类型：{attack_type} | ip: {attacker_ip}")
    except Exception as e:
        logger.error(f"❌ run_detection 执行失败！错误信息：{e}")
        return  # 直接退出，不执行后续逻辑

    if status == True:
        if isinstance(attacker_ip, dict):
            attacker_ip = attacker_ip.get("src", "unknown")
        packet_info['attack_type'] = attack_type

        # 通过 WebSocket 推送告警
        key = f"{attacker_ip}-{attack_type}"
        now = time.time()
        if key in _last_broadcast_time and now - _last_broadcast_time[key] < BROADCAST_INTERVAL:
            logger.info(f"⏱️ 跳过重复广播：{key}")
            return
        _last_broadcast_time[key] = now
        logger.info(f"🚨【规则检测】检测到攻击！类型: {attack_type}，源IP: {attacker_ip}")
        alert_message = {
            "time": time.time(),
            "timestamp": time.time(),
            "status": "ALERT",
            "attack": attack_type,
            "src_ip": attacker_ip,
            "level": "critical",
            "type": attack_type,
            "detail": {"src": attacker_ip}
        }
        try:
            if main_event_loop and main_event_loop.is_running():
                asyncio.run_coroutine_threadsafe(ws_manager.broadcast(alert_message), main_event_loop)
            else:
                logger.error("事件循环不可用，无法推送 WebSocket")
        except Exception as e:
            logger.error(f"❌ WebSocket 推送失败: {e}")

    elif status == 'suspected':
        if isinstance(attacker_ip, dict):
            attacker_ip = attacker_ip.get("src", "unknown")
        packet_info['attack_type'] = attack_type
        # 通过 WebSocket 推送告警
        key = f"{attacker_ip}-{attack_type}"
        now = time.time()
        if key in _last_broadcast_time and now - _last_broadcast_time[key] < BROADCAST_INTERVAL:
            logger.info(f"⏱️ 跳过重复广播：{key}")
            return
        _last_broadcast_time[key] = now
        logger.info(f"⚠️【疑似攻击】类型: {attack_type}，源IP: {attacker_ip}")
        alert_message = {
            "time": time.time(),
            "timestamp": time.time(),
            "status": "SUSPECTED",
            "attack": attack_type,
            "src_ip": attacker_ip,
            "level": "warning",
            "type": attack_type,
            "detail": {"src": attacker_ip}
        }
        try:
            if main_event_loop and main_event_loop.is_running():
                asyncio.run_coroutine_threadsafe(ws_manager.broadcast(alert_message), main_event_loop)
            else:
                logger.error("事件循环不可用，无法推送 WebSocket")
        except Exception as e:
            logger.error(f"❌ WebSocket 推送失败: {e}")

    else:  # DetectStatus.NORMAL
        packet_info['attack_type'] = "Normal"




SECRET_KEY = "jwt-secret-key"
ALGORITHM = "HS256"
USERS_FILE = Path(__file__).resolve().parent / "auth" / "users.json"

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/ml", ml_pyod.app)
_capture_running = False
_capture_lock = threading.Lock()


@app.post("/config/scenario")
def set_scenario(item: dict, user: str = Depends(get_current_user)):
    scenario = item.get("scenario")
    logger.info(f"收到场景切换请求: {scenario}")
    detection_manager.load_attack_config("attack_config.yaml", scenario)
    logger.info(f"场景已切换: {scenario}")
    return {"message": f"已切换到场景 {scenario}"}


@app.on_event("startup")
def on_startup():
    """
    服务启动时加载攻击检测配置；失败则使用默认阈值
    """
    logger.info("on_startup: 开始加载配置")
    try:
        load_attack_config("attack_config.yaml")
        logger.info("✅ 已加载攻击检测配置")
    except Exception as e:
        logger.warning(f"⚠️ 加载检测配置失败：{e}，使用默认参数")

    # 记录当前运行中的事件循环，供跨线程调度协程
    global main_event_loop
    try:
        main_event_loop = asyncio.get_running_loop()
        logger.info("主事件循环已保存到 main_event_loop")
    except RuntimeError:
        logger.warning("无法获取运行中的事件循环")

class LoginRequest(BaseModel):
    username: str
    password: str

class CaptureRequest(BaseModel):
    iface: str = "en0"   # 前端可传入接口，不传则默认 en0

@app.post("/login")
def login(data: LoginRequest):
    logger.info("login: 用户尝试登录 username=%s", data.username)
    if not os.path.exists(USERS_FILE):
        logger.error("用户数据文件不存在")
        raise HTTPException(status_code=500, detail="用户数据文件不存在")
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    user_hash = users.get(data.username)
    if not user_hash or not verify_password(data.password, user_hash):
        logger.error("用户名或密码错误 username=%s", data.username)
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    from datetime import datetime, timedelta
    expire = datetime.utcnow() + timedelta(minutes=30)
    token = jwt.encode({"sub": data.username, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)
    logger.info("login: 用户登录成功 username=%s", data.username)
    result = {"access_token": token}
    logger.info("login result: %s", result)
    return result


@app.get("/me")
def get_user_info(user: str = Depends(get_current_user)):
    logger.info("get_user_info: 请求用户信息 user=%s", user)
    result = {"message": f"你好，{user}！欢迎使用网络攻击检测系统"}
    logger.info("get_user_info result: %s", result)
    return result


@app.post("/capture/start")
def start_capture_api(req: CaptureRequest, user: str = Depends(get_current_user)):
    """
    启动流量捕获。需要登录。
    """
    logger.info("start_capture_api: 请求启动捕获 iface=%s by user=%s", req.iface, user)
    global _capture_running
    with _capture_lock:
        if _capture_running:
            logger.error("start_capture_api: 捕获已在运行")
            raise HTTPException(status_code=400, detail="Capture already running")
        try:
            capture.check_sudo()
            capture.start_capture(interface=req.iface,
                                  packet_handler=my_packet_handler,
                                  block=False)
            # 启动检测前清理所有检测模块状态
            detection_manager.clear_all_states()
            _capture_running = True
            logger.info(f"capture started on {req.iface}")
            result = {"msg": f"capture started on {req.iface}"}
            logger.info("start_capture_api result: %s", result)
            return result
        except Exception as e:
            logger.error("start_capture_api: 捕获启动失败 %s", e)
            raise HTTPException(status_code=500, detail=str(e))


@app.post("/capture/stop")
def stop_capture_api(user: str = Depends(get_current_user)):
    """
    停止流量捕获。需要登录。
    """
    logger.info("stop_capture_api: 请求停止捕获 by user=%s", user)
    global _capture_running
    with _capture_lock:
        if not _capture_running:
            logger.error("stop_capture_api: 捕获未运行")
            raise HTTPException(status_code=400, detail="Capture not running")
        try:
            capture.stop_capture()
            _capture_running = False
            # 清除上次检测缓存
            _last_broadcast_time.clear()
            try:
                detection_manager.clear_all_states()
            except AttributeError:
                pass
            logger.info("capture stopped")
            result = {"msg": "capture stopped"}
            logger.info("stop_capture_api result: %s", result)
            return result
        except Exception as e:
            logger.error("stop_capture_api: 捕获停止失败 %s", e)
            raise HTTPException(status_code=500, detail=str(e))



@app.get("/capture/status")
def capture_status_api(user: str = Depends(get_current_user)):
    """
    查询流量捕获运行状态。
    """
    logger.info("capture_status_api: 当前运行状态=%s", _capture_running)
    result = {"running": _capture_running}
    logger.info("capture_status_api result: %s", result)
    return result



# ---------------- WebSocket: 实时告警推送 ----------------
@app.websocket("/ws/alerts")
async def alerts_ws(ws: WebSocket):
    """
    前端通过 ws://.../ws/alerts 建立连接，即可实时接收 JSON 告警。
    本端不处理来自前端的文本，只做心跳维持。
    """
    logger.info("WebSocket connect: client connected")
    await ws_manager.connect(ws)
    try:
        # 准备一个有效的 JSON 消息
        message = {
            "timestamp": time.time(),
            "status": "Test",
            "attack": "Test message from server",
            "src_ip": "127.0.0.1"
        }

        # 将消息序列化成 JSON 格式并发送
        await ws.send_text(json.dumps(message))  # 使用 json.dumps 确保发送有效的 JSON 格式
        logger.info("WebSocket initial test message sent: %s", message)

        while True:
            # 维持心跳；不关心前端消息内容
            await ws.receive_text()
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_manager.disconnect(ws)
        logger.info("WebSocket disconnect")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
