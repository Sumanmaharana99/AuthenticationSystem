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

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn: '7d'});
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
        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn: '7d'});
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

//Email verificaton controller - Send verification OTP to users email
export const sendVerifyOtp = async(req,res)=>{
    try {
        const {userId} = req.body;
        const user = await User.findById(userId);
        if(!user){
            return res.status(404).json({success: false, msg: "User not found ! Please register first"});
        }
        if(user.isVerified){
            return res.status(400).json({success: false, msg: "Account already verified"});
        }
        //Generate six digit OTP string 
        const  otp = Math.floor(100000 + Math.random() *900000).toString().toString();
         user.verifyOtp = otp;
         user.verifyOtpExpiredAt = Date.now() + 24*60*60*1000; // OTP valid for 24 hours
         await user.save();
         const mailOptions = {
            from : process.env.SENDERS_EMAIL,
            to : user.email,
            subject : "Account Verification OTP",
            text : `Your verification OTP is ${otp}. It is valid for 24 hours. Please do not share this OTP with anyone.` 
         }
         await transporter.sendMail(mailOptions);
         res.status(200).json({success: true, msg: "Verification OTP sent successfully"});

    } catch (error) {
        return res.status(500).json({success: false, msg: "Error in sending verification OTP", error: error.message});
        console.log(error.message);
    }
}
//After user inputs OTP, verify the email
export const verifyEmail = async(req,res)=>{
    const {userId, otp} = req.body;

    if(!userId || !otp) {
        return res.status(400).json({success: false, msg: "Please provide userId and OTP"});
    }
    try {
        const user = await User.findById(userId);
        if(!user) {
            return res.status(404).json({success: false, msg: "User not found"});
        }
        if(user.verifyOtp === '' || user.verifyOtp!== otp) {
            return res.status(400).json({success: false, msg: "Invalid OTP"});
        }
        if(user.verifyOtpExpiredAt < Date.now()){
            return res.status(400).json({success: false, msg: "OTP expired."});
        }
        user.isVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpiredAt = 0;
        await user.save();
        res.status(200).json({success: true, msg: "Email verified successfully"});    

    } catch (error) {
        res.status(500).json({success: false, msg: "Error in email verification controller", error: error.message});
        console.log(error.message);
    }
}
export default {
    register,
    login,
    logout,
    sendVerifyOtp,
    verifyEmail
};