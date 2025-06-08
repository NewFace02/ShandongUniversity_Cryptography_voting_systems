# tests/test_or_proof_exp_elgamal.py

from backend.crypto.OR_Proof import ORProof
from backend.crypto.elgamal import ExponentialElGamal, PublicKey
from backend.utils import crypto_utils
import random

def test_or_proof_exp_elgamal():
    print("🔐 正在测试 OR-Proof（Exponential ElGamal 版本）")

    elgamal = ExponentialElGamal(True)
    pk = elgamal.public_key
    prover = ORProof(pk)
    
    for m in [0, 1]:
        print(f"\n👉 测试 m = {m}")
        r,ciphertext = elgamal.encrypt(m)
        
        alpha, beta = ciphertext.alpha, ciphertext.beta
        # 第一步：生成两个承诺 com1 和 com2
        com1, com2 = prover.generate_proof_step1(m, (alpha, beta))

        # 模拟挑战（由计票方发出）
        challenge = random.randint(1, pk.p - 1)
        # 第二步：应对挑战，返回两个子挑战及响应
        cha1, resp1, cha2, resp2 = prover.generate_proof_step2(challenge, r)

        # 第三步：验证者验证 ZK 证明
        zk_result = ORProof.verify_proof(
            c=(alpha, beta),
            com1=com1,
            com2=com2,
            cha=challenge,
            cha1=cha1,
            cha2=cha2,
            resp1=resp1,
            resp2=resp2,
            pk_v=(pk.p, pk.q, pk.g, pk.y)  # 注意格式
        )
        assert zk_result.verified, f"❌ 零知识证明失败（m={m}）"

        print(f"✅ 零知识证明通过（m={m}）")
        print(zk_result)


if __name__ == "__main__":
    test_or_proof_exp_elgamal()
