from typing import Dict, Tuple
from ..crypto.elgamal import ExponentialElGamal, ElGamalCiphertext
from ..crypto.OR_Proof import ORProof
import random

class VoteController:
    def __init__(self):
        """初始化投票控制器"""
        self.elgamal = ExponentialElGamal(decrypt_enabled=False)  # 不需要解密功能
        
    def create_vote(self, plaintext: int, weight: int) -> Dict:
        """
        创建加密投票
        :param plaintext: 投票值 (0或1)
        :param weight: 投票权重
        :return: 加密投票及证明
        """
        if plaintext not in (0, 1):
            raise ValueError("Vote must be 0 or 1")
            
        # 加密投票
        r, ciphertext = self._encrypt_weighted_vote(plaintext, weight)
        
        #  生成ZKP
        zkp = self._generate_zkp(plaintext, r, ciphertext)
        
        return {
            "ciphertext": {
                "alpha": str(ciphertext.alpha),
                "beta": str(ciphertext.beta)
            },
            "zkp": zkp,
            "weight_signature": f"weight_{weight}"  # 实际应该使用签名
        }
        
    def _encrypt_weighted_vote(self, vote: int, weight: int) -> Tuple[int, ElGamalCiphertext]:
        """
        加密带权重的投票: (g^r, g^{m*w} * y^r)
        """
        # 投票值乘以权重
        weighted_vote = vote * weight
        # 使用ElGamal加密
        return self.elgamal.encrypt(weighted_vote)
        
    def _generate_zkp(self, vote: int, r: int, ciphertext: ElGamalCiphertext) -> Dict:
        """生成零知识证明"""
        prover = ORProof(self.elgamal.public_key)
        
        # 生成OR证明的第一步
        com1, com2 = prover.generate_proof_step1(
            vote, 
            (ciphertext.alpha, ciphertext.beta)
        )
        
        # 生成随机挑战
        challenge = random.randint(1, self.elgamal.pk.p - 1)
        
        # 生成OR证明的第二步
        cha1, resp1, cha2, resp2 = prover.generate_proof_step2(challenge, r)
        
        return {
            "com1": com1,
            "com2": com2,
            "cha1": str(cha1),
            "cha2": str(cha2),
            "resp1": str(resp1),
            "resp2": str(resp2)
        }