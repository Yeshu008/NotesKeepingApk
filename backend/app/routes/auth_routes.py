from flask import Blueprint, request, jsonify, current_app, abort
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from app.models import User, db
from app.schemas.user_schema import UserSignUpSchema, UserSignInSchema
from app.utils.validators import validate_json
from bcrypt import hashpw, gensalt, checkpw

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    validated_data, errors = validate_json(UserSignUpSchema, data)
    if errors:
        abort(400, description={'validation_errors': errors})

    if User.query.filter_by(user_email=validated_data.user_email).first():
        abort(409, description='Email already registered')

    hashed_password = hashpw(validated_data.password.encode('utf-8'), gensalt())

    new_user = User(
        user_name=validated_data.user_name,
        user_email=validated_data.user_email,
        password=hashed_password.decode('utf-8')
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        abort(500, description='Failed to create user')

    return jsonify({
        'message': 'User created successfully. Please log in.'
    }), 201


@auth_bp.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    validated_data, errors = validate_json(UserSignInSchema, data)
    if errors:
        abort(400, description={'validation_errors': errors})

    user = User.query.filter_by(user_email=validated_data.user_email).first()
    if not user:
        abort(401, description='Invalid credentials')

    if not checkpw(validated_data.password.encode('utf-8'), user.password.encode('utf-8')):
        abort(401, description='Invalid credentials')

    access_token = create_access_token(identity=user.user_id)
    refresh_token = create_refresh_token(identity=user.user_id)

    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'user_id': user.user_id,
            'user_name': user.user_name,
            'user_email': user.user_email
        }
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user_id = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': new_access_token}), 200

@auth_bp.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(user_id=current_user_id).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'user_id': user.user_id,
        'user_name': user.user_name,
        'user_email': user.user_email
    }), 200

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    current_app.blacklisted_tokens.add(jti)
    return jsonify({'message': 'Successfully logged out'}), 200
