const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {UserInputError} = require('apollo-server');

const {SECRET_KEY} = require('../../config');
const User = require('../../models/User');
const {validateResgisterInput,validateLoginInput} = require('../../util/validators');

function generateToken(user){
   return jwt.sign({
        id:res.id,
        email:user.email,
        username: user.username
    },SECRET_KEY, {expiresIn:'1h'});
}

module.exports = {
    Mutation: {
        async login(_, {username,password}){
            const {errors,valid} = validateLoginInput(username,password);
            
            if(!valid){
                throw new UserInputError('Errors',{errors});
            }
            
            const user = await User.findOne({username});

            if(!user){
                errors.general = 'User not found';
                throw new UserInputError('User not found', {erros});
            }

            const match = await bcrypt.compare(password,user.password);
            if(!match) {
                errors.general = 'Wrong credentials';
                throw new UserInputError('Wrong credentials', {erros});
            }

            const token = generateToken(user);
            return {
                ...user._doc,
                id:user._id,
                token
            };
        },
       async register(_, {registerInput: {username,email,password,confirmPassword}}, context, info){
            // TODO Validate user data
            const {valid, errors} = validateResgisterInput(username,email,password,confirmPassword);
            if(!valid){
                throw new UserInputError('Error',{errors});
            }
            // TODO Make sure user  doesnt already exist
            const user = User.findOne({username});
            if(user){
                throw new UserInputError('Usernamme is taken', {
                    errors: {
                        username: 'This username is taken'
                    }
                });
            }
            // TODO hash password and create and auth token
            password = await bcrypt.hash(password, 12);

            const newUser = new User({
                email,
                username,
                password,
                createdAt: new Date().toISOString()
            });

            const res = await newUser.save();

            const token = generateToken(res);

            return {
                ...res._doc,
                id:res._id,
                token
            };
        },
    }
};