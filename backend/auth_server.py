from flask import Flask, request, jsonify
from backend.auth.auth import CredentialVerifier
from backend.auth.blind_signature import BlindSigner
import os
import json
from backend.models.vote import Voter
from uuid import uuid4

app = Flask(__name__)
verifier = CredentialVerifier()

# 存储股东信息的文件路径
SHAREHOLDERS_FILE = os.path.join(os.path.dirname(__file__), "shareholders.json")

# 初始化股东数据
def init_shareholders():
    """初始化或加载股东数据"""
    if not os.path.exists(SHAREHOLDERS_FILE):
        default_shareholders = {
            "shareholders": {
                "shareholder_001": {
                    "name": "张三",
                    "uuid": str(uuid4()),
                    "voter_id": "shareholder_001",
                    "voter_type": "shareholder",
                    "weight": 5
                },
                "shareholder_002": {
                    "name": "李四",
                    "uuid": str(uuid4()),
                    "voter_id": "shareholder_002",
                    "voter_type": "shareholder",
                    "weight": 3
                },
                "shareholder_003": {
                    "name": "王五",
                    "uuid": str(uuid4()),
                    "voter_id": "shareholder_003",
                    "voter_type": "shareholder",
                    "weight": 2
                }
            }
        }
        with open(SHAREHOLDERS_FILE, "w") as f:
            json.dump(default_shareholders, f, indent=2, ensure_ascii=False)
    
    with open(SHAREHOLDERS_FILE, "r") as f:
        data = json.load(f)
        # 转换为 Voter 对象
        return {
            "shareholders": {
                voter_id: Voter(**info)
                for voter_id, info in data["shareholders"].items()
            }
        }

# 加载股东数据
shareholders_data = init_shareholders()

def _verify_voter_identity(voter_id: str) -> bool:
    """
    验证股东身份
    :param voter_id: 股东ID
    :return: 是否为有效股东
    """
    return voter_id in shareholders_data["shareholders"]

def _calculate_voter_weight(voter_id: str) -> int:
    """
    计算股东权重
    :param voter_id: 股东ID
    :return: 股东权重
    """
    if voter_id in shareholders_data["shareholders"]:
        return shareholders_data["shareholders"][voter_id]["weight"]
    return 0

# 添加股东管理接口
@app.route('/auth/shareholders', methods=['GET'])
def get_shareholders():
    """获取所有股东信息"""
    return jsonify(shareholders_data)

@app.route('/auth/shareholders/<voter_id>', methods=['GET'])
def get_shareholder(voter_id):
    """获取特定股东信息"""
    if voter_id in shareholders_data["shareholders"]:
        return jsonify(shareholders_data["shareholders"][voter_id])
    return jsonify({"error": "Shareholder not found"}), 404

@app.route('/auth/shareholders', methods=['POST'])
def add_shareholder():
    """添加新股东"""
    try:
        data = request.get_json()
        if not all(k in data for k in ["voter_id", "name", "weight"]):
            return jsonify({"error": "Missing required fields"}), 400
        
        voter_id = data["voter_id"]
        if voter_id in shareholders_data["shareholders"]:
            return jsonify({"error": "Shareholder ID already exists"}), 400
        
        # 创建新的Voter对象
        new_shareholder = Voter(
            name=data["name"],
            uuid=str(uuid4()),
            voter_id=voter_id,
            voter_type="shareholder",
            weight=int(data["weight"])
        )
        
        # 转换为字典并保存
        shareholders_data["shareholders"][voter_id] = {
            "name": new_shareholder.name,
            "uuid": new_shareholder.uuid,
            "voter_id": new_shareholder.voter_id,
            "voter_type": new_shareholder.voter_type,
            "weight": new_shareholder.weight
        }
        
        with open(SHAREHOLDERS_FILE, "w") as f:
            json.dump(shareholders_data, f, indent=2, ensure_ascii=False)
        
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth/request_credential', methods=['POST'])
def request_credential():
    """请求投票凭证"""
    try:
        data = request.get_json()
        if not all(k in data for k in ['voter_id', 'blinded_serial', 'voter_info']):
            return jsonify({"error": "Missing required fields"}), 400
        
        # 验证股东身份
        voter_id = data['voter_id']
        if not _verify_voter_identity(voter_id):
            return jsonify({
                "error": "Invalid voter ID",
                "message": "此ID不在股东名单中"
            }), 403
        
        # 转换并签名盲化消息
        try:
            blinded_msg = int(data['blinded_serial'])
            signed_blinded = verifier.sign_blinded_message(blinded_msg)
        except ValueError as e:
            return jsonify({
                "error": "Invalid blinded serial format",
                "message": str(e)
            }), 400
        
        # 生成凭证
        credential = {
            "voter_id": voter_id,
            "signed_blinded": str(signed_blinded),
            "weight": data['voter_info']['weight']
        }
        
        return jsonify(credential)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5001)