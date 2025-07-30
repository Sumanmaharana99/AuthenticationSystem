import express from 'express';
import User from '../models/User.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    const {name,email,password} = req.body;
        if(!name ||!email || !password){
            return res.status(400).json({success: false,msg : "Please fill the required fields"});
        }
    try {
        const userExists  = await User.findOne({email:email});
        if(userExists){
           return res.status(400).json({success: false, msg: "User already exists"});
        }
        const saltRound = await bcrypt.genSalt(10);
        const hashed_password = await bcrypt.hash(password,saltRound);
        const user = await User.create({name,email,password:hashed_password});
        await user.save();

        const token = jwt.sign({id:user_id.toString()},process.env.JWT_SECRET,{expiresIn: '7d'});
    } catch (error) {
        res.status(500).json({success: false, msg: "Error in register controller", error: error.message});
        console.log(error.message);
    }
}