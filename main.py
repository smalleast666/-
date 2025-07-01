# main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from pydantic import BaseModel
from auth import hash_password, verify_password, create_token, decode_token
import logging

from fastapi.middleware.cors import CORSMiddleware

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# 明确指定前端源地址
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 模拟数据库
users_db = {}
online_users = {}

class UserRegister(BaseModel):
    username: str
    password: str

class PublicKeyPayload(BaseModel):
    publicKey: str

@app.post("/api/user/register")
def register(data: UserRegister):
    if data.username in users_db:
        raise HTTPException(status_code=409, detail="用户名已存在")
    users_db[data.username] = {"password": hash_password(data.password), "public_key": None, "online": False}
    logger.info(f"User '{data.username}' registered. Current users: {list(users_db.keys())}")
    return {"message": "用户注册成功"}

@app.post("/api/user/login")
def login(data: UserRegister):
    try:
        logger.info(f"Login attempt for user: '{data.username}'")
        user = users_db.get(data.username)
        
        if not user or not verify_password(data.password, user["password"]):
            logger.warning(f"Login failed: Invalid credentials for '{data.username}'.")
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        
        logger.info(f"Password verified for user: '{data.username}'")

        # 创建Token
        token = create_token(data.username)
        logger.info(f"Token created successfully for '{data.username}'")
        
        return {
            "message": "登录成功",
            "accessToken": token,
            "user": {"username": data.username, "hasPublicKey": user["public_key"] is not None}
        }
    except Exception as e:
        # 捕获任何未预料到的异常，例如在create_token中发生的错误
        logger.error(f"FATAL ERROR during login for '{data.username}': {e}", exc_info=True)
        # 向前端返回一个标准的、JSON格式的500错误
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {e}")

# 其他路由保持不变
# ...

@app.post("/api/user/logout")
def logout(Authorization: str = Header(...)):
    username = decode_token(Authorization.replace("Bearer ", ""))
    if not username or username not in users_db:
        raise HTTPException(status_code=401, detail="无效Token")
    users_db[username]["online"] = False
    if username in online_users:
        del online_users[username]
    return {"message": "登出成功"}

# ... (其他路由)
