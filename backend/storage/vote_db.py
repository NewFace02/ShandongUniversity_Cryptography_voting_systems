import json
import os
from typing import List, Dict
from .merkle_tree import MerkleTree
from .hash_chain import HashChain
from datetime import datetime
import fcntl
import logging
from ..models.vote import Vote, EncryptedAnswer
from ..crypto.elgamal import ElGamalCiphertext

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

VOTE_DB_PATH = os.path.join(os.path.dirname(__file__), "votes.json")
HASH_CHAIN_PATH = os.path.join(os.path.dirname(__file__), "hash_chain.json")

# 哈希链实例
_hash_chain = HashChain()

def init_vote_db():
    """初始化投票数据库文件和哈希链"""
    os.makedirs(os.path.dirname(VOTE_DB_PATH), exist_ok=True)
    
    initial_data = {
        "votes": [],
        "merkle_root": None,
        "total_weight": 0
    }
    
    # 初始化投票数据库
    if not os.path.exists(VOTE_DB_PATH):
        with open(VOTE_DB_PATH, "w") as f:
            json.dump(initial_data, f, indent=2)
    
    # 初始化哈希链
    if not os.path.exists(HASH_CHAIN_PATH):
        with open(HASH_CHAIN_PATH, "w") as f:
            json.dump([], f)
    else:
        with open(HASH_CHAIN_PATH, "r") as f:
            _hash_chain.chain = json.load(f)


def _acquire_lock(f):
    """文件锁"""
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)

def _release_lock(f):
    """释放锁"""
    fcntl.flock(f.fileno(), fcntl.LOCK_UN)


from threading import Lock

# 添加内存锁以优化并发性能
_memory_lock = Lock()

def store_vote(ciphertext: Dict, zkp: Dict, weight_signature: str) -> Dict:
    """
    存储投票数据
    使用Vote和EncryptedAnswer模型结构
    """
    # 输入验证部分保持不变
    if not all([ciphertext, zkp, weight_signature]):
        raise ValueError("Missing required fields")
    
    if not isinstance(ciphertext, dict) or not isinstance(zkp, dict):
        raise TypeError("ciphertext and zkp must be dictionaries")
        
    if not isinstance(weight_signature, str):
        raise TypeError("weight_signature must be a string")
    
    if not all(k in ciphertext for k in ["alpha", "beta"]):
        raise ValueError("Invalid ciphertext format")

    try:
        # 使用模型结构构建投票记录
        encrypted_answer = EncryptedAnswer(
            choices=[ElGamalCiphertext(
                alpha=int(ciphertext["alpha"]), 
                beta=int(ciphertext["beta"])
            )],
            individual_proofs=[zkp]
        )
        
        vote = Vote(
            answers=[encrypted_answer],
            election_hash=weight_signature,
            election_uuid=datetime.now().isoformat()
        )
        
        # 序列化为JSON格式
        vote_dict = {
            "timestamp": vote.election_uuid,
            "ciphertext": {
                "alpha": str(vote.answers[0].choices[0].alpha),
                "beta": str(vote.answers[0].choices[0].beta)
            },
            "zkp": zkp,
            "weight_signature": vote.election_hash
        }

        # 使用内存锁和文件锁的双重保护
        with _memory_lock:
            with open(VOTE_DB_PATH, "r+") as f:
                try:
                    _acquire_lock(f)
                    
                    # 加载现有数据
                    try:
                        data = json.load(f)
                        if not isinstance(data, dict):
                            data = {"votes": [], "merkle_root": None, "total_weight": 0}
                    except json.JSONDecodeError:
                        data = {"votes": [], "merkle_root": None, "total_weight": 0}
                    
                    if "votes" not in data:
                        data["votes"] = []
                    
                    # 添加新投票并获取索引
                    vote_index = len(data["votes"])
                    data["votes"].append(vote_dict)
                    
                    # 更新哈希链
                    vote_str = json.dumps(vote_dict, sort_keys=True)
                    vote_hash = _hash_chain.add_block(vote_str)

                    # 构建新的Merkle树（仅用于验证）
                    merkle_tree = MerkleTree([json.dumps(v, sort_keys=True) for v in data["votes"]])
                    data["merkle_root"] = merkle_tree.get_root()  # 写入最新的merkle_root
                    proof = merkle_tree.get_proof(vote_index)
                    
                    # 获取当前投票的Merkle证明
                    proof = merkle_tree.get_proof(vote_index)

                    # 先写入数据确保一致性
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
                    
                    # 更新哈希链文件
                    with open(HASH_CHAIN_PATH, "w") as chain_file:
                        json.dump(_hash_chain.chain, chain_file)
                        
                    
                    return {
                        "index": vote_index,
                        "vote_hash": vote_hash,
                        "merkle_proof": proof
                    }
                    
                finally:
                    _release_lock(f)
                    
    except Exception as e:
        logger.error(f"Error storing vote: {str(e)}")
        raise



def get_all_votes() -> Dict:
    """获取所有投票记录"""
    try:
        with open(VOTE_DB_PATH, "r") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {
                    "votes": [],
                    "merkle_root": None,
                    "total_weight": 0
                }
            return data
    except (json.JSONDecodeError, FileNotFoundError) as e:
        logger.error(f"Error reading votes: {str(e)}")
        return {
            "votes": [],
            "merkle_root": None,
            "total_weight": 0
        }

def clear_votes():
    """清空投票数据（仅用于测试）"""
    try:
        initial_data = {
            "votes": [],
            "merkle_root": None,
            "total_weight": 0
        }
        
        with open(VOTE_DB_PATH, "w") as f:
            json.dump(initial_data, f, indent=2)
        
        _hash_chain.chain = []
        with open(HASH_CHAIN_PATH, "w") as f:
            json.dump([], f)
            
    except Exception as e:
        logger.error(f"Error clearing votes: {str(e)}")
        raise