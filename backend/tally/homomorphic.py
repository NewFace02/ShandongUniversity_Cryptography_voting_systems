"同态操作的实现"
from backend.utils.crypto_utils import mod_exp
from Crypto.Util import number
from backend.crypto.elgamal import ElGamalCiphertext,PublicKey

class HomomorphicOperations:
    def __init__(self, elgamal_params: PublicKey):
        self.params = elgamal_params
        self.p = elgamal_params.p
    
    def homomorphic_add(self, ciphertexts: list[ElGamalCiphertext]) -> ElGamalCiphertext:
        """
        同态加法：多个密文的乘积对应明文的和
        """
        total_alpha = 1
        total_beta = 1
        
        for c in ciphertexts:
            total_alpha = (total_alpha * c.alpha) % self.p
            total_beta = (total_beta * c.beta) % self.p
        
        return ElGamalCiphertext(total_alpha, total_beta)
    
    def homomorphic_add_scalar(self, ciphertext: ElGamalCiphertext, scalar: int) -> ElGamalCiphertext:
        """
        同态加常数（通过乘法实现）
        ciphertext: (alpha, beta)
        scalar: 要加的整数k（权重，目前是整数k是相应股东比别人多的票数）
        """
        alpha, beta = ciphertext
        g_k = mod_exp(self.params.g, scalar, self.p)
        new_beta = new_beta = (ciphertext.beta * g_k) % self.p
        return ElGamalCiphertext(ciphertext.alpha, new_beta)
    
    def rerandomize(self, ciphertext: ElGamalCiphertext, r: int = None) -> ElGamalCiphertext:
        """
        密文重随机化（不改变明文）
        (alpha * g^r, beta * y^r)
        """
        alpha, beta = ciphertext
        if r is None:
            r = number.getRandomRange(1, self.params.q-1)
        
        new_alpha = (ciphertext.alpha * mod_exp(self.params.g, r, self.p)) % self.p
        new_beta = (ciphertext.beta * mod_exp(self.params.y, r, self.p)) % self.p  # y = pk
        
        return ElGamalCiphertext(new_alpha, new_beta)