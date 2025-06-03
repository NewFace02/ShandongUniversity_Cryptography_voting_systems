"同态操作的实现"
from ..utils import mod_exp, inverse_mod
from Crypto.Util import number

class HomomorphicOperations:
    def __init__(self, elgamal_params):
        self.params = elgamal_params
        self.p = elgamal_params.p
    
    def homomorphic_add(self, ciphertexts):
        """
        同态加法：多个密文的乘积对应明文的和
        ciphertexts: [(alpha_i, beta_i)] 列表
        返回: (prod_alpha, prod_beta)
        """
        total_alpha = 1
        total_beta = 1
        
        for alpha, beta in ciphertexts:
            total_alpha = (total_alpha * alpha) % self.p
            total_beta = (total_beta * beta) % self.p
        
        return total_alpha, total_beta
    
    def homomorphic_add_scalar(self, ciphertext, scalar):
        """
        同态加常数（通过乘法实现）
        ciphertext: (alpha, beta)
        scalar: 要加的整数k（权重，目前是整数k是相应股东比别人多的票数）
        返回: (alpha, beta * g^k)
        """
        alpha, beta = ciphertext
        g_k = mod_exp(self.params.g, scalar, self.p)
        new_beta = (beta * g_k) % self.p
        return alpha, new_beta
    
    def rerandomize(self, ciphertext, r=None):
        """
        密文重随机化（不改变明文）
        (alpha * g^r, beta * y^r)
        """
        alpha, beta = ciphertext
        if r is None:
            r = number.getRandomRange(1, self.params.q-1)
        
        new_alpha = (alpha * mod_exp(self.params.g, r, self.p)) % self.p
        new_beta = (beta * mod_exp(self.params.pk, r, self.p)) % self.p
        
        return new_alpha, new_beta