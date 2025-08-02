import express from 'express';
import User from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js';

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

        const token = jwt.sign({id:user._id.toString()},process.env.JWT_SECRET,{expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'None' : 'Strict',
            maxAge: 7*24*60*60*1000
        });

        //Sending welcome email 
        const mailOptions = {
            from : process.env.SENDERS_EMAIL,
            to : email,
            subject : "Welcome to Our Authify",
            text : `Welcome to Authify, your account has been created successfully with Email ID : ${email} . Please keep your credentials safe.`

        }
        // Send the email
        await transporter.sendMail(mailOptions);

        res.status(201).json({success: true, msg: "User registered successfully", user: {
            id: user._id,
            name: user.name,
            email: user.email
        }});
    } catch (error) {
        res.status(500).json({success: false, msg: "Error in register controller", error: error.message});
        console.log(error.message);
    }
}

export const login = async(req,res)=>{
    const {email,password} = req.body;
    if(!email || !password){
        return res.status(400).json({success:false, msg :"Please fill the required fields"});
    }
    try {
        const user = await User.findOne({email : email});
        if(!user){
            return res.status(400).json({success: false, msg: "Invalid Creadintials"});
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if(!isPasswordMatch){
            return res.status(400).json({success: false, msg: "Invalid Creadintials"});
        }
        const token = jwt.sign({id:user._id.toString()},process.env.JWT_SECRET,{expiresIn: '7d'});
        res.cookie('token', token, {
            httpOnly: true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'None' : 'Strict',
            maxAge: 7*24*60*60*1000
        });
        res.status(200).json({success: true, msg: "Login successful"});

    } catch (error) {
        res.status(500).json({success: false, msg: "Error in login controller", error: error.message});
        console.log(error.message);
    }
}

export const logout = async (req,res)=>{
    try {
        res.clearCookie("token",{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'None' : 'Strict',
        });
       return  res.status(200).json({success: true, msg: "Logout successful"});
    
    } catch (error) {
        res.status(500).json({success: false, msg: "Error in logout controller", error: error.message});
        console.log(error.message);
    }
}
export default {
    register,
    login,
    logout
};