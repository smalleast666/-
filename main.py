# main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from pydantic import BaseModel
import logging

from auth import hash_password, verify_password, create_token, decode_token
from db import init_db
from models import User # 导入我们的MongoDB模型

from fastapi.middleware.cors import CORSMiddleware

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# --- 中间件配置 ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- 应用生命周期事件 ---
@app.on_event("startup")
async def on_startup():
    """应用启动时，初始化数据库连接"""
    await init_db()

# --- 状态管理 ---
# online_users 仍然保留在内存中，因为它代表临时的在线状态，不适合频繁写入数据库
online_users: dict[str, dict] = {}

# --- Pydantic 模型 ---
class UserRegister(BaseModel):
    username: str
    password: str

class PublicKeyPayload(BaseModel):
    publicKey: str

# --- API 端点 ---

@app.post("/api/user/register")
async def register(data: UserRegister):
    logger.info(f"Registration attempt for user: '{data.username}'")
    # 检查用户是否已存在
    existing_user = await User.find_one(User.username == data.username)
    if existing_user:
        raise HTTPException(status_code=409, detail="用户名已存在")
    
    # 创建新用户实例并插入数据库
    hashed_pwd = hash_password(data.password)
    new_user = User(username=data.username, password_hash=hashed_pwd)
    await new_user.insert()
    
    logger.info(f"User '{data.username}' registered successfully.")
    return {"message": "用户注册成功"}

@app.post("/api/user/login")
async def login(data: UserRegister):
    logger.info(f"Login attempt for user: '{data.username}'")
    # 从数据库中查找用户
    user = await User.find_one(User.username == data.username)
    
    if not user or not verify_password(data.password, user.password_hash):
        logger.warning(f"Login failed: Invalid credentials for '{data.username}'.")
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    logger.info(f"Password verified for user: '{data.username}'")
    token = create_token(data.username)
    
    return {
        "message": "登录成功",
        "accessToken": token,
        "user": {"username": user.username, "hasPublicKey": user.public_key is not None}
    }

@app.post("/api/users/me/key")
async def upload_key(data: PublicKeyPayload, Authorization: str = Header(...)):
    username = decode_token(Authorization.replace("Bearer ", ""))
    if not username:
        raise HTTPException(status_code=401, detail="无效Token")
    
    user = await User.find_one(User.username == username)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    # 更新用户的公钥并保存到数据库
    user.public_key = data.publicKey
    await user.save()
    
    return {"message": "公钥更新成功"}

@app.get("/api/users/{username}/key")
async def get_user_key(username: str, Authorization: str = Header(...)):
    # ... (Token验证逻辑保持不变)
    user = await User.find_one(User.username == username)
    if not user or not user.public_key:
        raise HTTPException(status_code=404, detail="该用户未上传公钥")
    
    return {"username": username, "publicKey": user.public_key}

@app.get("/api/users/online")
async def get_online_users(Authorization: str = Header(...)):
    # ... (Token验证逻辑保持不变)
    # 直接返回内存中在线用户的列表
    return {
        "users": [{"username": u, "status": "online"} for u in online_users.keys()]
    }

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    username = None
    try:
        await ws.accept()
        
        ip, port = ws.client
        logger.info(f"WebSocket connection attempt from IP: {ip}, Port: {port}")

        token = ws.query_params.get("token")
        username = decode_token(token)
        
        # 验证用户是否存在于数据库中
        user = await User.find_one(User.username == username)
        if not user:
            await ws.close(code=1008)
            return

        online_users[username] = {
            "ws": ws,
            "ip": ip,
            "port": port
        }
        logger.info(f"User '{username}' connected from {ip}:{port}. Total online users: {len(online_users)}")

        while True:
            data = await ws.receive_json()
            if data["type"] == "message:send":
                to_user = data["payload"]["to"]
                # 检查接收方是否在线
                if to_user in online_users:
                    # 获取接收方的WebSocket对象并发送消息
                    recipient_ws = online_users[to_user]["ws"]
                    await recipient_ws.send_json({
                        "type": "message:receive",
                        "payload": {
                            "from": username,
                            "encryptedContent": data["payload"]["encryptedContent"]
                        }
                    })
                else:
                    logger.warning(f"Message from '{username}' to '{to_user}' failed: Recipient not online.")
    

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for user: {username}")
    except Exception as e:
        logger.error(f"WebSocket error for user {username}: {e}", exc_info=True)
    finally:
        # 清理工作：确保用户从在线列表中移除
        if username and username in online_users:
            del online_users[username]
            logger.info(f"User '{username}' removed from online list. Total online users: {len(online_users)}")
