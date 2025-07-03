# models.py
from beanie import Document, Indexed
from pydantic import Field
from typing import Optional
import uuid

class User(Document):
    """
    定义存储在MongoDB中的用户数据结构
    """
    # 我们使用UUID作为主键，而不是MongoDB默认的ObjectId，以便更好地管理
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    # Indexed确保username字段是唯一的，并为其创建索引以加快查询速度
    username: Indexed(str, unique=True)
    password_hash: str
    public_key: Optional[str] = None # 公钥是可选的

    class Settings:
        # 定义这个模型对应MongoDB中的哪个集合（collection）
        name = "users"
