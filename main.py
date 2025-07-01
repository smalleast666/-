from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Header
from pydantic import BaseModel
from auth import hash_password, verify_password, create_token, decode_token

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# 允许所有来源跨域（开发测试用，生产环境请限制具体域名）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 也可以限制具体前端地址
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
    return {"message": "用户注册成功"}

@app.post("/api/user/login")
def login(data: UserRegister):
    user = users_db.get(data.username)
    if not user or not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_token(data.username)
    return {
        "message": "登录成功",
        "accessToken": token,
        "user": {"username": data.username, "hasPublicKey": user["public_key"] is not None}
    }

@app.post("/api/user/logout")
def logout(Authorization: str = Header(...)):
    username = decode_token(Authorization.replace("Bearer ", ""))
    if not username:
        raise HTTPException(status_code=401, detail="无效Token")
    users_db[username]["online"] = False
    if username in online_users:
        del online_users[username]
    return {"message": "登出成功"}

@app.post("/api/users/me/key")
def upload_key(data: PublicKeyPayload, Authorization: str = Header(...)):
    username = decode_token(Authorization.replace("Bearer ", ""))
    if not username:
        raise HTTPException(status_code=401, detail="无效Token")
    users_db[username]["public_key"] = data.publicKey
    return {"message": "公钥更新成功"}

@app.get("/api/users/{username}/key")
def get_user_key(username: str, Authorization: str = Header(...)):
    current = decode_token(Authorization.replace("Bearer ", ""))
    if not current:
        raise HTTPException(status_code=401, detail="无效Token")
    user = users_db.get(username)
    if not user or not user["public_key"]:
        raise HTTPException(status_code=404, detail="该用户未上传公钥")
    return {"username": username, "publicKey": user["public_key"]}

@app.get("/api/users/online")
def get_online_users(Authorization: str = Header(...)):
    current = decode_token(Authorization.replace("Bearer ", ""))
    if not current:
        raise HTTPException(status_code=401, detail="无效Token")
    return {
        "users": [{"username": u, "status": "online"} for u, info in users_db.items() if info["online"]]
    }

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    print("🟡 客户端尝试建立 WebSocket 连接")

    try:
        token = ws.query_params.get("token")
        print("📦 收到 token:", token)
        username = decode_token(token)
        print("🧑‍💻 解析到用户名:", username)
        print("📃 当前注册用户列表:", list(users_db.keys()))

        # 验证token和用户是否有效
        if not username or username not in users_db:
            print("❌ 无效 Token 或用户未注册，拒绝连接")
            await ws.close(code=1008)
            return

        users_db[username]["online"] = True
        online_users[username] = ws
        print(f"✅ 用户 {username} 已上线，开始监听消息")

        while True:
            data = await ws.receive_json()
            if data["type"] == "message:send":
                to_user = data["payload"]["to"]
                print(f"✉️ {username} 向 {to_user} 发送消息")
                if to_user in online_users:
                    await online_users[to_user].send_json({
                        "type": "message:receive",
                        "payload": {
                            "from": username,
                            "encryptedContent": data["payload"]["encryptedContent"]
                        }
                    })
                else:
                    print(f"⚠️ 发送失败，用户 {to_user} 不在线")

    except WebSocketDisconnect:
        print(f"⚠️ 用户 {username} 已断开连接")
        users_db[username]["online"] = False
        if username in online_users:
            del online_users[username]
    except Exception as e:
        print(f"🚨 WebSocket异常：{e}")
        if username in online_users:
            del online_users[username]
        users_db[username]["online"] = False
        await ws.close(code=1011)
