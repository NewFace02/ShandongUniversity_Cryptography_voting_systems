from dataclasses import dataclass
from typing import List
from ..crypto.elgamal import ElGamalCiphertext
from ..crypto.OR_Proof import ZKProof_01
from dataclasses import dataclass, asdict

# 定义了一些结构体

@dataclass
class Voter:
    name: str
    uuid: str
    voter_id: str
    voter_type: str
    weight: int
    
    def to_dict(self):
        """转换为字典格式"""
        return asdict(self)
    
@dataclass
class EncryptedAnswer:
    choices: List[ElGamalCiphertext]
    individual_proofs: List[ZKProof_01]

@dataclass
class Vote:
    answers: List[EncryptedAnswer]
    election_hash: str
    election_uuid: str
