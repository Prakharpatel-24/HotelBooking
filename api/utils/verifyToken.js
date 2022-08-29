import jwt from 'jsonwebtoken';
import {createError} from '../utils/error.js';

export const verifyToken = (req,res,next)=>{
    const token = req.cookies.access_token;

    // if no token, means u are not authenticates
    if(!token)
    {
        return next(createError(401, "You are not authenticated"))
    }

    //if we have token we need to verify
    // (err,user) --> this part will be returned
    // this user has {id:user._id, isAdmin:user.isAdmin} --from controllers auth

    jwt.verify(token,process.env.JWT, (err,user)=>{
        if(err) return next(createError(403, "Token Invalid!"));
        req.user = user;
        next();
    })
}

export const verifyUser = (req,res,next)=>{
    verifyToken(req,res ,next, ()=>{
        if(req.user.id === req.params.id || req.user.isAdmin){
            next()
        }else{
            if(err) return next(createError(403,"You are not AUTHORIZED"))
        }
    })
}


export const verifyAdmin = (req, res, next) => {
    verifyToken(req, res, next, () => {
      if (req.user.isAdmin) {
        next();
      } else {
        return next(createError(403, "You are not authorized!"));
      }
    });
  };