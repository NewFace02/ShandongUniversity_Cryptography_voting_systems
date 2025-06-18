import pytest
from backend.vote.controller import TallyController
from backend.storage.vote_db import store_vote, clear_votes
from backend.crypto.elgamal import ElGamalCiphertext
import json

@pytest.fixture
def tally_controller():
    """初始化计票控制器"""
    return TallyController()

@pytest.fixture(autouse=True)
def setup_and_cleanup():
    """每个测试前后清理环境"""
    clear_votes()
    yield
    clear_votes()

def test_tally_initialization(tally_controller):
    """测试计票控制器初始化"""
    assert tally_controller.elgamal is not None
    assert tally_controller.homomorphic is not None

def test_empty_tally(tally_controller):
    """测试空投票情况"""
    result = tally_controller.tally_votes()
    assert "error" in result
    assert result["error"] == "No votes found"

def test_single_vote_tally(tally_controller):
    """测试单个投票计票"""
    # 使用真实的ElGamal加密
    elgamal = tally_controller.elgamal
    plaintext = 1  # 表示投1票
    r, ciphertext = elgamal.encrypt(plaintext)  # 获取随机数r和密文

    store_vote(
        ciphertext={"alpha": str(ciphertext.alpha), "beta": str(ciphertext.beta)},
        zkp={"r": str(r), "plaintext": str(plaintext)},  # 存储r便于验证
        weight_signature="test_weight"
    )
    
    result = tally_controller.tally_votes()
    
    assert "error" not in result
    assert result["total_votes"] == 1
    assert result["result"] == plaintext  # 应该解密回原始投票值
    assert "proof" in result
    assert "final_cipher" in result

def test_multiple_votes_tally(tally_controller):
    """测试多个投票计票"""
    elgamal = tally_controller.elgamal
    votes = []
    plaintexts = [0, 1, 1]  # 测试不同投票值
    
    # 存储多个真实加密的投票
    for plaintext in plaintexts:
        r, ciphertext = elgamal.encrypt(plaintext)
        vote_data = store_vote(
            ciphertext={"alpha": str(ciphertext.alpha), "beta": str(ciphertext.beta)},
            zkp={"r": str(r), "plaintext": str(plaintext)},
            weight_signature="1"  # 权重为1
        )
        votes.append(vote_data)
    
    result = tally_controller.tally_votes()
    
    assert "error" not in result
    assert result["total_votes"] == len(plaintexts)
    assert result["result"] == sum(plaintexts)  # 结果应该是投票值之和
    assert isinstance(result["total_weight"], int)
    assert "proof" in result
    assert "final_cipher" in result

def test_weighted_tally(tally_controller):
    """测试加权计票"""
    elgamal = tally_controller.elgamal
    weights = [1, 2, 3]  # 不同权重
    plaintext = 1  # 都投1票
    
    for weight in weights:
        r, ciphertext = elgamal.encrypt(plaintext*weight)
        print(plaintext*weight)
        store_vote(
            ciphertext={"alpha": str(ciphertext.alpha), "beta": str(ciphertext.beta)},
            zkp={"r": str(r), "plaintext": str(plaintext)},
            weight_signature=f"weight_{weight}"
        )
    
    result = tally_controller.tally_votes()
    
    assert "error" not in result
    assert result["total_votes"] == len(weights)
    # 结果应该是 plaintext * 每个权重的和
    assert result["result"] == plaintext * sum(weights)
    assert result["total_weight"] == sum(weights)

def test_homomorphic_properties(tally_controller):
    """测试同态性质"""
    elgamal = tally_controller.elgamal
    
    # 测试两个已知值
    plaintext1, plaintext2 = 1, 1
    r1, cipher1 = elgamal.encrypt(plaintext1)
    r2, cipher2 = elgamal.encrypt(plaintext2)
    
    vote1 = store_vote(
        ciphertext={"alpha": str(cipher1.alpha), "beta": str(cipher1.beta)},
        zkp={"r": str(r1), "plaintext": str(plaintext1)},
        weight_signature="1"
    )
    
    vote2 = store_vote(
        ciphertext={"alpha": str(cipher2.alpha), "beta": str(cipher2.beta)},
        zkp={"r": str(r2), "plaintext": str(plaintext2)},
        weight_signature="1"
    )
    
    result = tally_controller.tally_votes()
    
    assert "error" not in result
    assert result["total_votes"] == 2
    assert result["result"] == plaintext1 + plaintext2  # 验证同态加法正确性
    assert "proof" in result

def test_tally_proof_verification(tally_controller):
    """测试计票证明验证"""
    elgamal = tally_controller.elgamal
    plaintext = 1
    r, ciphertext = elgamal.encrypt(plaintext)
    
    store_vote(
        ciphertext={"alpha": str(ciphertext.alpha), "beta": str(ciphertext.beta)},
        zkp={"r": str(r), "plaintext": str(plaintext)},
        weight_signature="test"
    )
    
    result = tally_controller.tally_votes()
    
    assert "proof" in result
    proof = result["proof"]
    assert "type" in proof
    assert proof["type"] == "chaum-pedersen"
    # 验证证明中包含必要字段
    assert all(k in proof for k in ["A1", "A2", "challenge", "response", 
                                   "g", "p", "public_key"])

if __name__ == "__main__":
    pytest.main(["-v", __file__])