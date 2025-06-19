from flask import Blueprint, request, jsonify
from .controller import VoteController
from ..storage.vote_db import store_vote
from ..auth.auth import CredentialVerifier
from ..models.vote import Voter
import requests

vote_bp = Blueprint('vote', __name__)
vote_controller = VoteController()
verifier = CredentialVerifier()  # 添加验证器实例


@vote_bp.route('/cast', methods=['POST'])
def cast_vote():
    """投票接口"""
    try:
        data = request.get_json()
        
        # 验证输入
        if not all(k in data for k in ['vote', 'weight']):
            return jsonify({"error": "Missing required fields"}), 400
            
        # 创建加密投票
        vote_data = vote_controller.create_vote(
            plaintext=int(data['vote']),
            weight=int(data['weight'])
        )
        
        # 存储投票
        result = store_vote(
            ciphertext=vote_data["ciphertext"],
            zkp=vote_data["zkp"],
            weight_signature=vote_data["weight_signature"]
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@vote_bp.route('/submit', methods=['POST'])
def submit_vote():
    """提交投票的API接口"""
    try:
        data = request.get_json()
        required_fields = ['vote', 'weight', 'credential']
        
        if not all(k in data for k in required_fields):
            return jsonify({"error": "Missing required fields"}), 400
            
        # 1. 验证投票资格
        credential = data['credential']
        if not verifier.verify_credential(credential):
            return jsonify({"error": "Invalid credential"}), 403
            
        # 2. 创建加密投票
        vote_data = vote_controller.create_vote(
            plaintext=int(data['vote']),
            weight=int(data['weight'])
        )
        
        # 3. 将投票数据发送到计票中心
        tally_response = requests.post(
            'http://localhost:5002/tally/submit',
            json={
                'vote_data': vote_data,
                'credential': credential
            }
        )
        
        if tally_response.status_code != 200:
            return jsonify({"error": "Tally center rejected vote"}), 400
            
        return jsonify(tally_response.json())
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500