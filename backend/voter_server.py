from flask import Flask, request, jsonify
from backend.vote.controller import VoteController
from backend.crypto.OR_Proof import ORProof
from backend.auth.auth import CredentialVerifier
import requests

app = Flask(__name__)
vote_controller = VoteController()

@app.route('/vote', methods=['POST'])
def submit_vote():
    """股东投票接口"""
    try:
        data = request.get_json()
        required_fields = ['vote', 'weight', 'credential']
        
        if not all(k in data for k in required_fields):
            return jsonify({"error": "Missing required fields"}), 400
        
        # 1. 创建加密投票
        vote_data = vote_controller.create_vote(
            plaintext=int(data['vote']),
            weight=int(data['weight'])
        )
        
        # 2. 发送到计票中心
        response = requests.post(
            'http://localhost:5002/tally/submit',
            json={
                'vote_data': vote_data,
                'credential': data['credential']
            }
        )
        
        if response.status_code != 200:
            return jsonify({"error": "Tally center rejected vote"}), 400
            
        return jsonify(response.json())
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify/<int:vote_index>', methods=['GET'])
def verify_vote(vote_index):
    """验证投票"""
    try:
        response = requests.get(f'http://localhost:5002/verify/{vote_index}')
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(port=5000)