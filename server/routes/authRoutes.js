import express from 'express';
import authControllers from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

authRouter.route('/register').post(authControllers.register);
authRouter.route('/login').post(authControllers.login);
authRouter.route('/logout').post(authControllers.logout);
authRouter.route('/send-verify-otp').post(userAuth, authControllers.sendVerifyOtp);
authRouter.route('/verify-account').post(userAuth,authControllers.verifyEmail);
export default authRouter;