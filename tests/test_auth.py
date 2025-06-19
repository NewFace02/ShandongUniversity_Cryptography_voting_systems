import pytest
from backend.auth.auth import CredentialVerifier

@pytest.fixture
def verifier():
    """初始化验证器"""
    return CredentialVerifier()

@pytest.fixture(autouse=True)
def setup_cleanup(verifier):
    """每次测试前清理环境"""
    verifier.clear_used_serials()
    yield
    verifier.clear_used_serials()

def test_credential_generation_and_verification(verifier):
    """测试凭证生成和验证的完整流程"""
    # 1. 生成凭证
    credential = verifier.generate_credential()
    
    # 验证凭证格式
    assert "serial_number" in credential
    assert "signature" in credential
    
    # 2. 验证凭证
    assert verifier.verify_credential(credential)

def test_duplicate_credential(verifier):
    """测试重复使用凭证"""
    # 生成一个凭证
    credential = verifier.generate_credential()
    
    # 第一次验证应该成功
    assert verifier.verify_credential(credential)
    
    # 重复使用应该失败
    assert not verifier.verify_credential(credential)

def test_tampered_credential(verifier):
    """测试篡改的凭证"""
    credential = verifier.generate_credential()
    
    # 篡改签名
    credential["signature"] += 1
    
    # 验证应该失败
    assert not verifier.verify_credential(credential)

def test_blind_signature_properties(verifier):
    """测试盲签名的性质"""
    # 生成两个不同的凭证
    cred1 = verifier.generate_credential()
    cred2 = verifier.generate_credential()
    
    # 验证序列号不同
    assert cred1["serial_number"] != cred2["serial_number"]
    
    # 验证签名不同
    assert cred1["signature"] != cred2["signature"]
    
    # 两个凭证都应该有效
    assert verifier.verify_credential(cred1)
    assert verifier.verify_credential(cred2)

def test_invalid_credential_format(verifier):
    """测试无效的凭证格式"""
    # 缺少必要字段
    invalid_cred = {"serial_number": 123}
    assert not verifier.verify_credential(invalid_cred)
    
    # 错误的数据类型
    invalid_cred = {
        "serial_number": "not a number",
        "signature": "not a number"
    }
    assert not verifier.verify_credential(invalid_cred)

if __name__ == "__main__":
    pytest.main(["-v", __file__])