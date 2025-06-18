from typing import Dict, List, Tuple
from ..crypto.elgamal import ExponentialElGamal, ElGamalCiphertext
from ..storage.vote_db import get_all_votes
from ..tally.homomorphic import HomomorphicOperations
from ..audit.logger import AuditLogger
from ..models.vote import Vote
import json
import random
import hashlib
from ..utils.crypto_utils import mod_exp

class TallyController:
    def __init__(self):
        """初始化计票控制器"""
        # 启用解密功能的ElGamal实例
        self.elgamal = ExponentialElGamal(decrypt_enabled=True)
        # 同态运算工具
        self.homomorphic = HomomorphicOperations(self.elgamal.public_key)
        
    def tally_votes(self) -> Dict:
        """
        获取并计票所有投票
        返回计票结果和证明
        """
        # 获取所有投票记录
        vote_data = get_all_votes()
        votes = vote_data["votes"]
        
        if not votes:
            return {"error": "No votes found"}
            
        # 收集所有有效密文
        valid_ciphertexts = []
        total_weight = 0
        
        for vote in votes:
            # 验证ZKP
            if not self._verify_vote_zkp(vote):
                continue
                
            try:
            # 从字符串正确转换为整数
                ciphertext = ElGamalCiphertext(
                    alpha=int(vote["ciphertext"]["alpha"]),
                    beta=int(vote["ciphertext"]["beta"])
                )
            
                weight = self._verify_weight_signature(vote["weight_signature"])
                if weight > 0:
                    total_weight += weight
                    valid_ciphertexts.append(ciphertext)

            except (ValueError, KeyError) as e:
                continue
        
        # 同态累加所有有效票
        if not valid_ciphertexts:
            return {"error": "No valid votes to tally"}
        
        final_tally = self.homomorphic.homomorphic_add(valid_ciphertexts)
        result = self.elgamal.decrypt_to_value(final_tally)
    
        tally_proof = self._generate_tally_proof(final_tally, result)
    
        self._audit_tally_result(result, total_weight, tally_proof)
    
        return {
                "total_votes": len(valid_ciphertexts),
                "total_weight": total_weight,
                "result": result,
                "proof": tally_proof,
                "final_cipher": {
                    "alpha": str(final_tally.alpha),
                    "beta": str(final_tally.beta)
                }
            }
        

    def _verify_vote_zkp(self, vote: Dict) -> bool:
        """验证投票的零知识证明"""
        try:
            zkp = vote["zkp"]
            ciphertext = vote["ciphertext"]
            # 验证零知识证明
            # TODO: 实现具体的ZKP验证逻辑
            return True
        except Exception as e:
            print(f"ZKP verification failed: {e}")
            return False

    def _verify_weight_signature(self, weight_signature: str) -> int:
        """验证权重签名并返回权重值"""
        try:
            # 从签名中提取权重值
            if weight_signature.startswith('weight_'):
                weight = int(weight_signature.split('_')[1])
                return weight
            return 1  # 默认权重为1
        except Exception as e:
            print(f"Weight signature verification failed: {e}")
            return 0

    def _generate_tally_proof(self, final_tally: ElGamalCiphertext, result: int) -> Dict:
        """
        生成 Chaum-Pedersen 证明
        证明：知道私钥 x，满足 g^x = y 且 alpha^x = beta/g^m
        """
        g = self.elgamal.pk.g
        p = self.elgamal.pk.p
        x = self.elgamal._sk  # 私钥
    
        # 1. 选择随机数
        w = random.randint(1, p-2)
    
        # 2. 计算两个承诺
        A1 = mod_exp(g, w, p)  # g^w
        A2 = mod_exp(final_tally.alpha, w, p)  # alpha^w
    
        # 3. 计算挑战
        data = str(final_tally.alpha) + str(final_tally.beta) + str(A1) + str(A2)
        challenge = int(hashlib.sha256(data.encode()).hexdigest(), 16) % p
    
        # 4. 计算响应
        response = (w + challenge * x) % (p-1)
    
        # 5. 返回完整证明
        return {
            "type": "chaum-pedersen",
            "A1": str(A1),
            "A2": str(A2),
            "challenge": str(challenge),
            "response": str(response),
            "g": str(g),
            "p": str(p),
            "public_key": str(self.elgamal.pk.y),
            # 额外信息，便于验证
            "alpha": str(final_tally.alpha),
            "beta": str(final_tally.beta),
            "result": str(result)
        }

    def _audit_tally_result(self, result: int, total_weight: int, proof: Dict):
        """记录计票结果到审计日志"""
        audit_data = {
            "timestamp": "...",
            "result": result,
            "total_weight": total_weight,
            "proof": proof
        }
        # TODO: 调用审计日志记录
        # AuditLogger.log_tally_result(audit_data)