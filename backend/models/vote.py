from dataclasses import dataclass
from typing import List
from ..crypto.elgamal import ElGamalCiphertext
from ..crypto.OR_Proof import ZKProof_01

# 定义了一些结构体

@dataclass
class Voter:
    name: str
    uuid: str
    voter_id: str  # email or phone
    voter_type: str  # 'email', 'phone', etc.

@dataclass
class EncryptedAnswer:
    choices: List[ElGamalCiphertext]
    individual_proofs: List[ZKProof]
    overall_proof: ZKProof

@dataclass
class Vote:
    answers: List[EncryptedAnswer]
    election_hash: str
    election_uuid: str
