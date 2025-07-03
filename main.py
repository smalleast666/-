# main.py
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from pydantic import BaseModel
import logging
import asyncio

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
    # 验证token，确保只有登录用户才能调用此接口
    current_user = decode_token(Authorization.replace("Bearer ", ""))
    if not current_user:
        raise HTTPException(status_code=401, detail="无效Token")

    # 构建包含IP和端口的在线用户列表
    # 我们不应该把请求者自己包含在列表里
    user_list = [
        {
            "username": username,
            "ip": info["ip"],
            "port": info["port"]
        }
        for username, info in online_users.items() if username != current_user
    ]
    
    return {"users": user_list}


# --- 辅助函数 ---
def get_formatted_online_list(exclude_username: str = None) -> list:
    """获取格式化的在线用户列表，可以排除某个用户。"""
    user_list = []
    for username, info in online_users.items():
        if username != exclude_username:
            user_list.append({
                "username": username,
                "ip": info["ip"],
                "port": info["port"]
            })
    return user_list

async def broadcast(message: dict, exclude_username: str = None):
    """向所有在线用户（可排除某个用户）广播消息。"""
    tasks = [
        info["ws"].send_json(message)
        for username, info in online_users.items()
        if username != exclude_username
    ]
    if tasks:
        await asyncio.gather(*tasks)


# --- WebSocket 端点 ---
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    username = None
    try:
        await ws.accept()
        ip, port = ws.client
        
        token = ws.query_params.get("token")
        username = decode_token(token)
        
        user = await User.find_one(User.username == username)
        if not user:
            await ws.close(code=1008)
            return

        # --- 关键逻辑 ---

        # 1. 向新上线的用户发送当前所有其他在线用户的列表
        online_list = get_formatted_online_list(exclude_username=username)
        await ws.send_json({
            "type": "friends:online_list",
            "payload": online_list
        })
        logger.info(f"Sent online list to '{username}'.")

        # 2. 向所有其他用户广播“新用户上线”的通知
        await broadcast({
            "type": "friend:online",
            "payload": {"username": username, "ip": ip, "port": port}
        }, exclude_username=username)
        logger.info(f"Broadcasted 'friend:online' for '{username}'.")

        # 3. 将新用户加入在线列表
        online_users[username] = {"ws": ws, "ip": ip, "port": port}
        logger.info(f"User '{username}' connected. Total online: {len(online_users)}")

        # 4. 循环监听消息 (逻辑不变)
        while True:
            data = await ws.receive_json()
                        if data["type"] == "message:send":
                to_user = data["payload"]["to"]
                if to_user in online_users:
                    await online_users[to_user]["ws"].send_json({
                        "type": "message:receive",
                        "payload": { "from": username, "encryptedContent": data["payload"]["encryptedContent"] }
                    })
            elif data["type"] == "file:send":
                to_user = data["payload"]["to"]
                if to_user in online_users:
                    # Forward the entire file payload to the recipient
                    await online_users[to_user]["ws"].send_json({
                        "type": "file:receive",
                        "payload": {
                            "from": username,
                            "fileName": data["payload"]["fileName"],
                            "fileType": data["payload"]["fileType"],
                            "encryptedFile": data["payload"]["encryptedFile"],
                            "encryptedKey": data["payload"]["encryptedKey"],
                        }
                    })
                    logger.info(f"Relayed file from '{username}' to '{to_user}'.")

    except WebSocketDisconnect:
        logger.info(f"User '{username}' disconnected.")
    except Exception as e:
        logger.error(f"WebSocket error for user '{username}': {e}", exc_info=True)
    finally:
        # 5. 清理并广播“用户下线”通知
        if username and username in online_users:
            del online_users[username]
            await broadcast({
                "type": "friend:offline",
                "payload": { "username": username }
            })
            logger.info(f"Broadcasted 'friend:offline' for '{username}'.")
