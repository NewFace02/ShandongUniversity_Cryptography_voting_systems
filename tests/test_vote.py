import pytest
from backend.vote.controller import VoteController
from backend.crypto.elgamal import ElGamalCiphertext
from backend.crypto.OR_Proof import ORProof

@pytest.fixture
def vote_controller():
    """初始化投票控制器"""
    return VoteController()

def test_vote_initialization(vote_controller):
    """测试投票控制器初始化"""
    assert vote_controller.elgamal is not None
    assert not vote_controller.elgamal._sk  # 确保没有加载私钥

def test_create_vote_valid_input(vote_controller):
    """测试创建有效投票"""
    # 测试投票值0
    vote_data = vote_controller.create_vote(plaintext=0, weight=1)
    _verify_vote_data(vote_data)
    
    # 测试投票值1
    vote_data = vote_controller.create_vote(plaintext=1, weight=1)
    _verify_vote_data(vote_data)

def test_create_vote_invalid_input(vote_controller):
    """测试创建无效投票"""
    # 测试无效的投票值
    with pytest.raises(ValueError, match="Vote must be 0 or 1"):
        vote_controller.create_vote(plaintext=2, weight=1)
    
    with pytest.raises(ValueError, match="Vote must be 0 or 1"):
        vote_controller.create_vote(plaintext=-1, weight=1)

def test_weighted_vote_encryption(vote_controller):
    """测试带权重的投票加密"""
    vote = 1
    weight = 3
    r, ciphertext = vote_controller._encrypt_weighted_vote(vote, weight)
    
    assert isinstance(r, int)
    assert isinstance(ciphertext, ElGamalCiphertext)
    assert hasattr(ciphertext, 'alpha')
    assert hasattr(ciphertext, 'beta')

def test_zkp_generation(vote_controller):
    """测试零知识证明生成"""
    vote = 1
    weight = 1
    r, ciphertext = vote_controller._encrypt_weighted_vote(vote, weight)
    
    # 生成ZKP
    zkp = vote_controller._generate_zkp(vote, r, ciphertext)
    
    # 验证ZKP格式
    assert isinstance(zkp, dict)
    assert all(k in zkp for k in ['com1', 'com2', 'cha1', 'cha2', 'resp1', 'resp2'])
    
    # 验证ZKP正确性
    prover = ORProof(vote_controller.elgamal.public_key)
    result = ORProof.verify_proof(
        c=(ciphertext.alpha, ciphertext.beta),
        com1=zkp['com1'],
        com2=zkp['com2'],
        cha=(int(zkp['cha1']) + int(zkp['cha2'])) % vote_controller.elgamal.pk.p,
        cha1=int(zkp['cha1']),
        cha2=int(zkp['cha2']),
        resp1=int(zkp['resp1']),
        resp2=int(zkp['resp2']),
        pk_v=(vote_controller.elgamal.pk.p,
              vote_controller.elgamal.pk.q,
              vote_controller.elgamal.pk.g,
              vote_controller.elgamal.pk.y)
    )
    
    assert result.verified

def test_different_weights(vote_controller):
    """测试不同权重的投票"""
    vote = 1
    weights = [1, 2, 3, 5, 10]
    
    for weight in weights:
        vote_data = vote_controller.create_vote(vote, weight)
        assert vote_data['weight_signature'] == f"weight_{weight}"
        _verify_vote_data(vote_data)

def _verify_vote_data(vote_data):
    """验证投票数据格式"""
    # 验证基本结构
    assert isinstance(vote_data, dict)
    assert all(k in vote_data for k in ['ciphertext', 'zkp', 'weight_signature'])
    
    # 验证密文格式
    assert all(k in vote_data['ciphertext'] for k in ['alpha', 'beta'])
    
    # 验证ZKP格式
    assert all(k in vote_data['zkp'] for k in [
        'com1', 'com2', 'cha1', 'cha2', 'resp1', 'resp2'
    ])
    
    # 验证权重签名格式
    assert vote_data['weight_signature'].startswith('weight_')

if __name__ == "__main__":
    pytest.main(["-v", __file__])