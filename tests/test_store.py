import pytest
import json
import os
from backend.storage.vote_db import init_vote_db, store_vote, get_all_votes, clear_votes
from backend.storage.merkle_tree import MerkleTree
from datetime import datetime
"python3 -m pytest tests/test_store.py -v"

@pytest.fixture(autouse=True)
def setup_and_cleanup():
    """每个测试前后清理环境"""
    clear_votes()
    yield
    clear_votes()

def test_init_vote_db():
    """测试数据库初始化"""
    init_vote_db()
    data = get_all_votes()
    
    assert isinstance(data, dict)
    assert "votes" in data
    assert "merkle_root" in data
    assert "total_weight" in data
    assert len(data["votes"]) == 0

def test_store_single_vote():
    """测试存储单个投票"""
    # 模拟加密投票数据
    ciphertext = {
        "alpha": "123",
        "beta": "456"
    }
    zkp = {
        "commitment": "789",
        "challenge": "012",
        "response": "345"
    }
    weight_signature = "test_signature"

    # 存储投票
    result = store_vote(ciphertext, zkp, weight_signature)
    
    # 验证返回结果格式
    assert isinstance(result, dict)
    assert "index" in result
    assert "vote_hash" in result
    assert "merkle_proof" in result
    assert result["index"] == 0  # 第一个投票的索引应为0

    # 验证存储的数据
    stored_data = get_all_votes()
    assert len(stored_data["votes"]) == 1
    stored_vote = stored_data["votes"][0]
    
    assert stored_vote["ciphertext"] == ciphertext
    assert stored_vote["zkp"] == zkp
    assert stored_vote["weight_signature"] == weight_signature
    assert "timestamp" in stored_vote

def test_store_multiple_votes():
    """测试存储多个投票"""
    votes_data = []
    
    # 存储3个测试投票
    for i in range(3):
        ciphertext = {
            "alpha": str(i*2),
            "beta": str(i*2+1)
        }
        zkp = {
            "commitment": str(i),
            "challenge": str(i+1),
            "response": str(i+2)
        }
        weight_signature = f"signature_{i}"
        
        result = store_vote(ciphertext, zkp, weight_signature)
        votes_data.append(result)
        
        # 验证返回的索引是否正确
        assert result["index"] == i
        # 验证是否包含Merkle证明
        assert isinstance(result["merkle_proof"], list)
        
    # 验证所有存储的投票
    stored_data = get_all_votes()
    assert len(stored_data["votes"]) == 3
    
    # 验证Merkle根是否存在
    assert stored_data["merkle_root"] is not None
    
    # 验证每个投票的数据完整性
    for i, vote in enumerate(stored_data["votes"]):
        assert vote["ciphertext"]["alpha"] == str(i*2)
        assert vote["ciphertext"]["beta"] == str(i*2+1)
        assert vote["zkp"]["commitment"] == str(i)
        assert vote["weight_signature"] == f"signature_{i}"

def test_merkle_proof_verification():
    """测试Merkle证明的正确性"""
    votes_data = []
    
    # 存储测试投票
    for i in range(5):
        result = store_vote(
            ciphertext={"alpha": str(i), "beta": str(i)},
            zkp={"data": str(i)},
            weight_signature=str(i)
        )
        votes_data.append(result)

    stored_data = get_all_votes()
    
    # 验证每个投票的Merkle证明
    for i, result in enumerate(votes_data):
        vote = stored_data["votes"][i]
        assert MerkleTree.verify_proof(
            json.dumps(vote, sort_keys=True),  # 加上 sort_keys=True
            result["merkle_proof"],
            stored_data["merkle_root"]
    )

def test_concurrent_vote_storage():
    """测试并发存储情况"""
    from concurrent.futures import ThreadPoolExecutor
    import threading
    
    def store_test_vote(i):
        return store_vote(
            ciphertext={"alpha": str(i), "beta": str(i)},
            zkp={"data": str(i)},
            weight_signature=str(i)
        )
    
    # 并发存储10个投票
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_vote = {executor.submit(store_test_vote, i): i for i in range(10)}
    
    # 验证所有投票都被正确存储
    stored_data = get_all_votes()
    assert len(stored_data["votes"]) == 10

def test_error_handling():
    """测试错误处理"""
    # 测试空值
    with pytest.raises(ValueError):
        store_vote(None, None, None)
    
    # 测试类型错误
    with pytest.raises(TypeError):
        store_vote(
            ciphertext="invalid",  # 应该是字典
            zkp="invalid",        # 应该是字典
            weight_signature=123   # 应该是字符串
        )
    
    # 测试无效密文格式
    with pytest.raises(ValueError):
        store_vote(
            ciphertext={"invalid": "format"},
            zkp={"data": "test"},
            weight_signature="test"
        )

if __name__ == "__main__":
    pytest.main(["-v", __file__])