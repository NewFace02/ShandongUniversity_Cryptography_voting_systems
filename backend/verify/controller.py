from typing import Dict
from ..storage.vote_db import get_all_votes
from ..storage.merkle_tree import MerkleTree
from ..crypto.OR_Proof import ORProof
import json
from ..crypto.elgamal import ExponentialElGamal, PublicKey

class VerifyController:
    def __init__(self):
        """初始化验证控制器"""
        # 初始化 ElGamal 实例以获取公钥
        self.elgamal = ExponentialElGamal(decrypt_enabled=False)
        self.pk = self.elgamal.public_key  # 获取公钥对象
    def verify_vote(self, vote_index: int) -> Dict:
        """验证投票的存在性和完整性"""
        try:
            # 1. 获取投票数据
            votes = get_all_votes()
            if vote_index >= len(votes["votes"]):
                return {"verified": False, "error": "Vote index out of range"}
                
            vote = votes["votes"][vote_index]
            merkle_root = votes["merkle_root"]
            
            # 2. 验证ZKP
            if not self._verify_zkp(vote):
                return {"verified": False, "error": "Invalid ZKP"}
                
            # 3. 验证权重
            if not self._verify_weight(vote):
                return {"verified": False, "error": "Invalid weight"}
            
            # 4. 验证Merkle证明
            merkle_tree = MerkleTree([
                json.dumps(v, sort_keys=True) 
                for v in votes["votes"]
            ])
            
            proof = merkle_tree.get_proof(vote_index)
            vote_str = json.dumps(vote, sort_keys=True)
            
            if not MerkleTree.verify_proof(vote_str, proof, merkle_root):
                return {"verified": False, "error": "Invalid Merkle proof"}
                
            return {
                "verified": True,
                "vote": vote,
                "merkle_proof": proof
            }
            
        except Exception as e:
            return {"verified": False, "error": str(e)}
            
    def _verify_zkp(self, vote: Dict) -> bool:
        """验证投票的零知识证明"""
        try:
            ciphertext = vote["ciphertext"]
            zkp = vote["zkp"]
            
            # 从密文中提取 alpha, beta
            alpha = int(ciphertext["alpha"])
            beta = int(ciphertext["beta"])
            
            # 从ZKP中提取证明参数
            com1 = zkp["com1"]
            com2 = zkp["com2"]
            cha1 = int(zkp["cha1"])
            cha2 = int(zkp["cha2"])
            resp1 = int(zkp["resp1"])
            resp2 = int(zkp["resp2"])
            
            # 调用OR_Proof验证
            result = ORProof.verify_proof(
                c=(alpha, beta),
                com1=com1,
                com2=com2,
                cha=cha1 + cha2,
                cha1=cha1,
                cha2=cha2,
                resp1=resp1,
                resp2=resp2,
                pk_v=(self.pk.p, self.pk.q, self.pk.g, self.pk.y)
            )
            
            return result.verified
            
        except Exception as e:
            print(f"ZKP verification failed: {e}")
            return False
            
    def _verify_weight(self, vote: Dict) -> bool:
        """验证投票权重"""
        try:
            weight_signature = vote["weight_signature"]
            # 实际应该验证权重签名
            return weight_signature.startswith("weight_")
        except Exception as e:
            print(f"Weight verification failed: {e}")
            return False