from typing import Dict
from ..storage.vote_db import get_all_votes
from ..storage.merkle_tree import MerkleTree
import json

class VerifyController:
    def verify_vote(self, vote_index: int) -> Dict:
        """验证投票的存在性和完整性"""
        try:
            votes = get_all_votes()
            if vote_index >= len(votes["votes"]):
                return {"verified": False, "error": "Vote index out of range"}
                
            vote = votes["votes"][vote_index]
            merkle_root = votes["merkle_root"]
            
            # 重建 Merkle 树并获取证明
            merkle_tree = MerkleTree([
                json.dumps(v, sort_keys=True) 
                for v in votes["votes"]
            ])
            
            proof = merkle_tree.get_proof(vote_index)
            
            # 验证 Merkle 证明
            vote_str = json.dumps(vote, sort_keys=True)
            is_valid = MerkleTree.verify_proof(
                vote_str,
                proof,
                merkle_root
            )
            
            if not is_valid:
                return {"verified": False, "error": "Invalid Merkle proof"}
                
            return {
                "verified": True,
                "vote": vote,
                "merkle_proof": proof
            }
            
        except Exception as e:
            return {"verified": False, "error": str(e)}