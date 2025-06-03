"指数变体elgamal算法"

from Crypto.Util import number
from backend.utils.crypto_utils import mod_exp, inverse_mod
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
    def __init__(self, p=None, g=None, q=None):
        """
        初始化加密参数
        p: 大素数
        g: 生成元
        q: 子群阶 (p-1的素因子)
        """
        if p and g and q:
            self.p = p
            self.g = g
            self.q = q
        else:
            self.generate_parameters(2048)  # 默认2048位安全
    
    def generate_parameters(self, bits):
        """生成安全参数"""
        self.q = number.getPrime(bits)
        # 确保p=2q+1也是素数
        while True:
            self.p = 2 * self.q + 1
            if number.isPrime(self.p):
                break
        # 寻找生成元
        self.g = self.find_generator()
    
    def find_generator(self):
        """在循环群中寻找生成元"""
        for h in range(2, self.p-1):
            g = mod_exp(h, 2, self.p)
            if g != 1:
                return g
        raise RuntimeError("Generator not found")
    
    def keygen(self) -> Tuple[PublicKey, int]:
        """生成公私钥对"""
        self.sk = number.getRandomRange(1, self.q-1)  # 私钥
        self.pk = mod_exp(self.g, self.sk, self.p)    # 公钥
        return PublicKey(self.p, self.g, self.q, self.pk), self.sk
    
    def encrypt(self, m: int, pk: int = None, r: int = None) -> ElGamalCiphertext:
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
        y_r = mod_exp(pk, r, self.p)        # y^r
        g_m = mod_exp(self.g, m, self.p)    # g^m
        beta = (g_m * y_r) % self.p         # g^m * y^r
        
        return ElGamalCiphertext(alpha, beta)
    
    def decrypt(self, ciphertext: ElGamalCiphertext, sk: int = None) -> int:
        """
        解密密文 (alpha, beta)二元组
        返回 g^m (需额外步骤恢复m)
        """
        alpha, beta = ciphertext.alpha, ciphertext.beta
        if sk is None:
            sk = self.sk
        
        s = mod_exp(alpha, sk, self.p)  # s = alpha^sk = g^{r*sk}
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