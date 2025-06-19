import pytest
from backend.verify.controller import VerifyController
from backend.storage.vote_db import store_vote, clear_votes
from backend.crypto.elgamal import ExponentialElGamal
from backend.crypto.OR_Proof import ORProof
import random

@pytest.fixture
def verify_controller():
    return VerifyController()

@pytest.fixture(autouse=True)
def setup_cleanup():
    clear_votes()
    yield
    clear_votes()

def test_verify_valid_vote(verify_controller):
    """测试验证有效投票"""
    # 生成一个有效投票
    elgamal = ExponentialElGamal()
    plaintext = 1
    r, ciphertext = elgamal.encrypt(plaintext)
    
    # 生成ZKP
    prover = ORProof(elgamal.public_key)
    com1, com2 = prover.generate_proof_step1(plaintext, (ciphertext.alpha, ciphertext.beta))
    challenge = random.randint(1, elgamal.pk.p - 1)
    cha1, resp1, cha2, resp2 = prover.generate_proof_step2(challenge, r)
    
    # 存储投票
    vote_data = store_vote(
        ciphertext={"alpha": str(ciphertext.alpha), "beta": str(ciphertext.beta)},
        zkp={
            "com1": com1,
            "com2": com2,
            "cha1": str(cha1),
            "cha2": str(cha2),
            "resp1": str(resp1),
            "resp2": str(resp2)
        },
        weight_signature="weight_1"
    )
    
    # 验证投票
    result = verify_controller.verify_vote(0)
    assert result["verified"] == True