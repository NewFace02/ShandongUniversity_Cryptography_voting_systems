import json
import os
from typing import List, Dict
from .merkle_tree import MerkleTree
from .hash_chain import HashChain
from datetime import datetime

VOTE_DB_PATH = os.path.join(os.path.dirname(__file__), "votes.json")
HASH_CHAIN_PATH = os.path.join(os.path.dirname(__file__), "hash_chain.json")

# 哈希链实例
_hash_chain = HashChain()

def init_vote_db():
    """初始化投票数据库文件和哈希链"""
    os.makedirs(os.path.dirname(VOTE_DB_PATH), exist_ok=True)
    if not os.path.exists(VOTE_DB_PATH):
        with open(VOTE_DB_PATH, "w") as f:
            json.dump({
                "votes": [],
                "merkle_root": None,
                "total_weight": 0
            }, f)
    
    # 初始化哈希链
    if os.path.exists(HASH_CHAIN_PATH):
        with open(HASH_CHAIN_PATH, "r") as f:
            _hash_chain.chain = json.load(f)

def store_vote(ciphertext: Dict, zkp: Dict, weight_signature: str) -> Dict:
    """
    存储一条加密投票数据项
    :param ciphertext: {"alpha": ..., "beta": ...} ElGamal密文
    :param zkp: 零知识证明结构体
    :param weight_signature: 权重签名
    :return: 存储结果，包含投票索引和Merkle证明
    """
    vote = {
        "timestamp": datetime.now().isoformat(),
        "ciphertext": ciphertext,
        "zkp": zkp,
        "weight_signature": weight_signature
    }

    # 加载现有数据
    with open(VOTE_DB_PATH, "r") as f:
        data = json.load(f)
    
    # 添加新投票
    vote_index = len(data["votes"])
    data["votes"].append(vote)
    
    # 更新哈希链
    vote_hash = _hash_chain.add_block(json.dumps(vote))
    
    # 重新计算Merkle树
    vote_data = [json.dumps(v) for v in data["votes"]]
    merkle_tree = MerkleTree(vote_data)
    data["merkle_root"] = merkle_tree.get_root()
    
    # 保存数据
    with open(VOTE_DB_PATH, "w") as f:
        json.dump(data, f, indent=2)
    
    # 保存哈希链
    with open(HASH_CHAIN_PATH, "w") as f:
        json.dump(_hash_chain.chain, f)
    
    # 返回投票索引和Merkle证明
    return {
        "index": vote_index,
        "vote_hash": vote_hash,
        "merkle_proof": merkle_tree.get_proof(vote_index)
    }

def verify_vote(index: int) -> Dict:
    """
    验证某条投票记录的完整性
    :param index: 投票索引
    :return: 验证结果
    """
    with open(VOTE_DB_PATH, "r") as f:
        data = json.load(f)
    
    if index >= len(data["votes"]):
        raise IndexError("投票索引越界")
        
    vote = data["votes"][index]
    vote_data = json.dumps(vote)
    
    # 验证哈希链
    chain_valid = _hash_chain.verify_chain([json.dumps(v) for v in data["votes"][:index+1]])
    
    # 验证Merkle证明
    merkle_tree = MerkleTree([json.dumps(v) for v in data["votes"]])
    merkle_proof = merkle_tree.get_proof(index)
    merkle_valid = MerkleTree.verify_proof(vote_data, merkle_proof, data["merkle_root"])
    
    return {
        "vote": vote,
        "chain_valid": chain_valid,
        "merkle_valid": merkle_valid,
        "merkle_proof": merkle_proof
    }

def get_all_votes() -> Dict:
    """返回所有投票记录及验证信息"""
    with open(VOTE_DB_PATH, "r") as f:
        return json.load(f)

def clear_votes():
    """清空投票数据（仅用于测试）"""
    init_vote_db()
    _hash_chain.chain = []
    with open(HASH_CHAIN_PATH, "w") as f:
        json.dump([], f)