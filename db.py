# db.py
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from models import User # 导入我们刚刚创建的模型

async def init_db():
    """
    初始化数据库连接和Beanie ODM
    """
    # 创建一个到MongoDB服务器的异步客户端
    # "mongodb://localhost:27017" 是MongoDB的默认地址
    # "secure_im_db" 是我们将要使用的数据库名称
    client = AsyncIOMotorClient("mongodb://localhost:27017/secure_im_db")

    # 初始化Beanie，将数据库客户端与我们的文档模型关联起来
    # Beanie会自动检查并创建索引
    await init_beanie(database=client.get_database(), document_models=[User])
    print("Database connection initialized.")

