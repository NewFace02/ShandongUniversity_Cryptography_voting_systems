import json
import os
from typing import List, Dict

VOTE_DB_PATH = os.path.join(os.path.dirname(__file__), "votes.json")

# 确保文件夹和文件存在
os.makedirs(os.path.dirname(VOTE_DB_PATH), exist_ok=True)
if not os.path.exists(VOTE_DB_PATH):
    with open(VOTE_DB_PATH, "w") as f:
        json.dump([], f)

def init_vote_db():
    """初始化投票数据库文件（如不存在则创建）"""
    if not os.path.exists(VOTE_DB_PATH):
        with open(VOTE_DB_PATH, "w") as f:
            json.dump([], f)

def store_vote(ciphertext: Dict, zkp: Dict, signature: str):
    """
    存储一条加密投票数据项
    :param ciphertext: {"alpha": ..., "beta": ...}
    :param zkp: 零知识证明结构体
    :param signature: 权重签名（认证返回）
    """
    vote = {
        "ciphertext": ciphertext,
        "zkp": zkp,
        "signature": signature
    }

    # 加载并追加
    with open(VOTE_DB_PATH, "r") as f:
        votes = json.load(f)
    votes.append(vote)
    
    # 保存
    with open(VOTE_DB_PATH, "w") as f:
        json.dump(votes, f, indent=2)

def get_all_votes() -> List[Dict]:
    """返回所有投票记录"""
    with open(VOTE_DB_PATH, "r") as f:
        return json.load(f)

def clear_votes():
    """清空投票数据（开发调试用）"""
    with open(VOTE_DB_PATH, "w") as f:
        json.dump([], f)

def get_vote_by_index(index: int) -> Dict:
    """根据索引获取单条投票记录"""
    votes = get_all_votes()
    if index < 0 or index >= len(votes):
        raise IndexError("投票索引越界")
    return votes[index]