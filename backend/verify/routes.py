from flask import Blueprint, request, jsonify
from .controller import VerifyController

verify_bp = Blueprint('verify', __name__)
verify_controller = VerifyController()

@verify_bp.route('/verify/<int:vote_index>', methods=['GET'])
def verify_vote(vote_index):
    """验证投票API"""
    result = verify_controller.verify_vote(vote_index)
    return jsonify(result)