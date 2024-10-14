#!/usr/bin/env python3

from flask import request, session, jsonify, abort
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

@app.before_request
def check_if_logged_in():
    open_access_list = ['signup', 'login', 'check_session']
    if request.endpoint not in open_access_list and not session.get('user_id'):
        abort(401, description='Unauthorized')

class Signup(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')
        image_url = request_json.get('image_url')
        bio = request_json.get('bio')

        if not username or not password:
            return {'error': 'Username and password are required.'}, 422

        user = User(username=username, image_url=image_url, bio=bio)
        user.password_hash = password  # Hash the password

        try:
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return user.to_dict(), 201
        except IntegrityError:
            return {'error': 'Username already exists.'}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        return {}, 401

class Login(Resource):
    def post(self):
        request_json = request.get_json()
        username = request_json.get('username')
        password = request_json.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {'error': 'Invalid credentials'}, 401

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return {}, 204

class RecipeIndex(Resource):
    def get(self):
        user = User.query.get(session['user_id'])
        return [recipe.to_dict() for recipe in user.recipes], 200

    def post(self):
        request_json = request.get_json()
        title = request_json.get('title')
        instructions = request_json.get('instructions')
        minutes_to_complete = request_json.get('minutes_to_complete')

        if not title or not instructions or not minutes_to_complete:
            return {'error': 'All fields are required.'}, 422

        try:
            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user_id=session['user_id'],
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except IntegrityError:
            return {'error': 'Unable to create recipe.'}, 422

# Register resources
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipe_index')
