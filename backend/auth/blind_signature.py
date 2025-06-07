#此文件实现基于RSA的盲签名
from Crypto.PublicKey import RSA
import math
from dataclasses import dataclass
from typing import Tuple
from ..config import load_rsa_keys
@dataclass
class BlindSigner:
    def __init__(self):
        """初始化盲签名者，加载 RSA 公私钥"""
        self.n, self.e,self.d = load_rsa_keys()

    def sign(self, blinded_message: int) -> int:
        # 真实的 RSA 签名为：s = blinded_message^d mod n
        return pow(blinded_message, self.d, self.n)

class BlindClient:
    def __init__(self):
        n, e, _ = load_rsa_keys()
        self.n = n
        self.e = e
#注意这里的r不是self.r
    def blind(self, message: int) -> Tuple[int, int]:
        from Crypto.Util.number import getPrime, inverse
        r = getPrime(128)
        while True:
            if r < self.n and math.gcd(r, self.n) == 1:
                break
            r = getPrime(128)
        blinded = (message * pow(r, self.e, self.n)) % self.n
        return blinded, r

    def unblind(self, signed_blinded: int, r: int) -> int:
        from Crypto.Util.number import inverse
        return (signed_blinded * inverse(r, self.n)) % self.n
