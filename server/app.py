#!/usr/bin/env python3

from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        
        valid_fields = ['username', 'image_url','password','bio']
        
        for field in json:
            if field not in valid_fields:
                return AttributeError('Invalid fields')
            
        try:
            user = User(
            username=json['username'],
            image_url=json['image_url'],
            bio=json['bio']
            )
            
        
            user.password_hash = json['password']
            
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            
            return user.to_dict(), 201
            
        except:
            return make_response(
                {
                    "error":"User not valid"
                },422
            )
        
        

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session and session['user_id']:
            user = User.query.filter(User.id == session['user_id']).first()
            
            return user.to_dict(),200
        else:
            return make_response({
                "error":"User not authenticated"
            },401)

class Login(Resource):
    def post(self):
        user = User.query.filter(User.username == request.json['username']).first()
        
        if not user:
            return make_response(
                {"error":"User not found"}, 401
            )
            
        if user.authenticate(request.json['password']):
            session['user_id'] = user.id            
            
            return user.to_dict(),200
        else:
            return make_response(
                {"error":"Invalid credentials"},401
            )

class Logout(Resource):
    def delete(self):
        if 'user_id' in session and session['user_id']:
            session['user_id'] = ""
            
            return {},204
        
        return make_response(
            {"error":"User not logged in"},401
        )

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session and session['user_id']:
            recipes = Recipe.query.all()
            
            return make_response(
                [recipe.to_dict() for recipe in recipes], 200
            )
        else:
            return make_response(
                {"error":"Unauthorized request"},401
            )
            
    def post(self):
        if 'user_id' in session and session['user_id']:
            json = request.get_json()
            
            try:
                recipe = Recipe(
                title=json['title'],
                instructions=json['instructions'],
                minutes_to_complete=json['minutes_to_complete'],
                user_id=session['user_id']
            )
            
                db.session.add(recipe)
                db.session.commit()
                
                return make_response(
                    recipe.to_dict(),
                    201
                )
            except:
                return make_response({
                    "error":"Recipe attributes not valid",
                }, 422)
            
        else:
            return make_response(
                    {"error":"Unauthorized request"},401
            )

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)