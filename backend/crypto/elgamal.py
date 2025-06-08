"指数变体elgamal算法"

from Crypto.Util import number
from backend.utils.crypto_utils import mod_exp, inverse_mod
from backend.config import load_elgamal_keys
from dataclasses import dataclass
from typing import Tuple

@dataclass
class ElGamalCiphertext:
    alpha: int
    beta: int


'可复用公钥结构'
@dataclass
class PublicKey:
    p: int
    g: int
    q: int
    y: int  # 即 pk = g^sk mod p

class ExponentialElGamal:
    def __init__(self,decrypt_enabled: bool = False):
        """从配置文件加载 ElGamal 公共参数"""
        self.p, self.g, self.y, self.x = load_elgamal_keys()
        self.q = (self.p - 1) // 2
        self.pk = PublicKey(self.p, self.g, self.q, self.y)

        # 安全改进：仅在需要时加载私钥
        self._sk = self.x if decrypt_enabled else None
        self.max_log_value = 1000  # 最大支持票数
    
    @property
    def public_key(self) -> PublicKey:
        """返回加载好的公钥"""
        return self.pk
    
    def encrypt(self, m: int, pk: PublicKey = None, r: int = None) -> Tuple[int, ElGamalCiphertext]:
        """
        加密消息 m
        m: 明文（整数）
        pk: 公钥（可选）
        r: 随机数（2<=r<=p-2）
        返回: (alpha, beta) = (g^r, g^m * y^r)
        """
        if pk is None:
            pk = self.pk
        if r is None:
            r = number.getRandomRange(1, self.q-1)
        
        alpha = mod_exp(self.g, r, self.p)  # g^r
        y_r = mod_exp(self.y, r, self.p)        # y^r
        g_m = mod_exp(self.g, m, self.p)    # g^m
        beta = (g_m * y_r) % self.p         # g^m * y^r

        return r, ElGamalCiphertext(alpha, beta)

    def decrypt(self, ciphertext: ElGamalCiphertext, sk: int = None) -> int:
        """
        解密密文 (alpha, beta)二元组
        返回 g^m (需额外步骤恢复m)
        需要初始化时启用解密功能
        """
        if self._sk is None:
            raise PermissionError("解密功能未启用")

        alpha, beta = ciphertext.alpha, ciphertext.beta
        
        s = mod_exp(alpha, self._sk, self.p)  # s = alpha^sk = g^{r*sk}
        s_inv = inverse_mod(s, self.p)      # s^{-1}
        g_m = (beta * s_inv) % self.p   # g^m = beta * s^{-1}
    
        return g_m
    
    def decrypt_to_value(self, ciphertext, max_possible=None):
        """
        解密并恢复原始消息m
        max_possible: 预期最大值（用于高效计算离散对数）
        """
        g_m = self.decrypt(ciphertext)
        return self.solve_discrete_log(g_m, max_possible)
    
    def solve_discrete_log(self, g_m, max_value=100):
        """
        通过穷举计算离散对数
        适用于小值域（如投票计票）
        票数小，穷举合适
        """
        
        if max_value is None:
            max_value = 100  # 默认支持100票
        
        accum = 1
        for m in range(0, max_value + 1):
            if accum == g_m:
                return m
            accum = (accum * self.g) % self.p
        raise ValueError("Discrete log solution not found in range")