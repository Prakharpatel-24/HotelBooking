import User from '../models/User.js';
import bcrypt from "bcryptjs";
import { createError } from '../utils/error.js';
import jwt from "jsonwebtoken";

// REGISTER
export const register = async (req,res,next)=>{
    try{
        // using bcrypt to hash password

        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);
        // ---------------------------------------

        const newUser = new User({
            username: req.body.username,
            email: req.body.email,
            password: hash,
        });

        await newUser.save();
        res.status(200).send("User has been created");
    }catch(err)
    {
        next(err);
    }
};


//  LOGIN
export const login = async (req,res,next)=>{
    try{
        const user = await User.findOne({username: req.body.username})
        if(!user) return next(createError(404,"User not found!"))

        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
        if(!isPasswordCorrect) return next(createError(400,"Wrong password or username "))
        
        // here we hash the information, and for each request we will share this jwt token to verify our identity
        // process.env.JWT --> This is secret key in .ENV file

        const token = jwt.sign({id:user._id, isAdmin:user.isAdmin},process.env.JWT)

        const{password, isAdmin, ...otherDetails} = user._doc;

        // we set token into cookie, so we install a package cookie-parser

        res.cookie("access_token",token,{
            httpOnly: true,
        }).status(200).json({...otherDetails});
    }catch(err)
    {
        next(err);
    }
};