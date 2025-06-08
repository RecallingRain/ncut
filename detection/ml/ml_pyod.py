# ml_pyod.py：使用 PyOD 对 CSV 数据进行静态异常检测的 FastAPI 服务模块
# 包含数据预处理、模型训练与预测、日志记录及前端接口
from fastapi import FastAPI, UploadFile, File, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pyod.models.knn import KNN
from pyod.models.iforest import IForest
from pyod.models.ecod import ECOD
from pyod.models.copod import COPOD
import pandas as pd
import io
import logging
import os
from datetime import datetime
import ipaddress
import numpy as np
import json
from sklearn.feature_selection import VarianceThreshold

def preprocess_data(df: pd.DataFrame):
    """执行特征选择、特征工程及方差筛选，返回预处理后的特征 DataFrame。"""
    # 基本特征选择：提取初始数值特征
    base_features = ['inter_arrival', 'packet_length', 'sess_pkt_count', 'sess_byte_count']
    df_sel = df[base_features].dropna().copy()

    # 时间戳特征工程：提取时、分、秒
    df_ts = pd.to_datetime(df['timestamp'], errors='coerce')
    df_sel['hour']   = df_ts.dt.hour.fillna(-1).astype(int)
    df_sel['minute'] = df_ts.dt.minute.fillna(-1).astype(int)
    df_sel['second'] = df_ts.dt.second.fillna(-1).astype(int)

    # IP 地址转换：将 IP 字符串转为整数
    df_sel['src_ip_int'] = df['src_ip'].apply(lambda x: int(ipaddress.ip_address(x)) if pd.notna(x) else 0)
    df_sel['dst_ip_int'] = df['dst_ip'].apply(lambda x: int(ipaddress.ip_address(x)) if pd.notna(x) else 0)

    # 端口号特征：填充并转换为整数
    df_sel['src_port'] = df['src_port'].fillna(0).astype(int)
    df_sel['dst_port'] = df['dst_port'].fillna(0).astype(int)

    # 协议独热编码
    df_sel = pd.concat([df_sel, pd.get_dummies(df['protocol'], prefix='proto')], axis=1)

    # TCP 标志位编码：分别提取 S,A,F,R,P,U
    for flag in ['S','A','F','R','P','U']:
        df_sel[f'tcp_flag_{flag}'] = df['tcp_flags'].fillna('').str.contains(flag).astype(int)

    # 载荷长度特征：hex 编码长度/2
    df_sel['payload_len'] = df['payload_raw'].fillna('').str.len().div(2).astype(int)

    # HTTP 特征：状态码、方法独热、消息体长度、头部数量
    df_sel['http_status'] = df['http_status'].fillna(0).astype(int)
    df_sel = pd.concat([df_sel, pd.get_dummies(df['method'], prefix='method')], axis=1)
    df_sel['body_len'] = df['http_body'].fillna('').str.len().astype(int)
    df_sel['headers_count'] = df['http_headers'].fillna('[]').apply(lambda s: len(json.loads(s)) if isinstance(s, str) else 0)

    # 布尔标志位特征
    for col in ['is_tls_heartbeat','is_login_failure','is_ssh_handshake_failure']:
        df_sel[col] = df[col].astype(int)

    # 方差筛选：移除低方差特征
    selector = VarianceThreshold(threshold=1e-6)
    X_var = selector.fit_transform(df_sel)
    kept = df_sel.columns[selector.get_support()]
    df_sel = pd.DataFrame(X_var, columns=kept)

    return df_sel

def run_models(X: np.ndarray, models: dict, df_sel=None):
    """训练并预测给定模型字典，每个模型返回预测标签、平均决策分数和分数细节。"""
    preds = {}
    scores = {}
    details = {}
    # 遍历所有模型
    for name, clf in models.items():
        # 模型训练
        logger.info(f"开始训练模型：{name}")
        clf.fit(X)
        # 设置特征名，避免特征名警告
        if hasattr(clf, 'feature_names_in_'):
            clf.feature_names_in_ = df_sel.columns.to_numpy()
        # 获取决策分数，若不存在使用 decision_function
        try:
            ds = clf.decision_scores_
        except AttributeError:
            ds = clf.decision_function(X)
        # 模型预测
        preds[name] = clf.predict(X)
        # 计算并记录平均决策分数
        scores[name] = float(np.mean(ds))
        details[name] = ds
        # 记录异常样本数量
        logger.info(f"模型 {name} 检测到异常样本：{sum(preds[name])} 条")
    return preds, scores, details

# 日志系统配置：记录到同目录 ml_pyod.log 文件
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.info("=== ml_pyod 模块已加载 ===")
log_path = os.path.join(os.path.dirname(__file__), 'ml_pyod.log')
handler = logging.FileHandler(log_path)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
print(f"日志路径：{log_path}")
logger.info("日志系统初始化完成")

# 创建 FastAPI 应用
app = FastAPI()

# HTTP 请求日志中间件：记录每次请求及响应状态
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"收到请求：{request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"请求完成：{request.method} {request.url.path} -> 状态码 {response.status_code}")
    return response

# 静态文件挂载：将 static 目录映射到 /static 路径
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Favicon 路由：防止浏览器自动请求 favicon.ico 而返回 404
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(os.path.join(static_dir, "favicon.ico"))

# Pydantic 模型：定义接口返回的检测结果结构
class DetectionResult(BaseModel):
    filename: str
    anomalies: list
    scores: dict

# 异常检测 API 路由：接收 CSV 文件，返回异常详情及模型分数
@app.post("/detect", response_model=DetectionResult)
async def detect_anomalies(file: UploadFile = File(...)):
    try:
        # 读取上传的 CSV 文件
        contents = await file.read()
        logger.info(f"接收到文件：{file.filename}")
        df = pd.read_csv(io.StringIO(contents.decode('utf-8')))
        logger.info(f"已加载 DataFrame，行数：{len(df)}，列数：{len(df.columns)}")

        # 数据预处理
        df_selected = preprocess_data(df)
        X = df_selected.values
        # 运行所有模型
        model_instances = {
            'KNN': KNN(),
            'IForest': IForest(contamination=0.1),
            'ECOD': ECOD(contamination=0.1),
            'COPOD': COPOD(contamination=0.1)
        }
        preds_dict, scores_dict, details_dict = run_models(X, model_instances)

        # 获取异常数据的索引
        anomaly_indices = df_selected.index[preds_dict['KNN'] == 1].tolist()
        logger.info(f"返回异常样本索引，共 {len(anomaly_indices)} 条")

        # 构建异常详情列表，包含各模型分数
        anomaly_details = []
        for idx in anomaly_indices:
            detail = {
                'index': int(idx),
                'knn_score': float(details_dict['KNN'][idx]),
                'iforest_score': float(details_dict['IForest'][idx]),
                'ecod_score': float(details_dict['ECOD'][idx]),
                'copod_score': float(details_dict['COPOD'][idx])
            }
            anomaly_details.append(detail)
        logger.info(f"异常样本详情及分数：{anomaly_details}")

        return DetectionResult(filename=file.filename, anomalies=anomaly_details, scores=scores_dict)
    except Exception as e:
        logger.error(f"detect_anomalies 出错：{e}", exc_info=True)
        return JSONResponse(content={"error": str(e)}, status_code=500)