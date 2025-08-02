import express from 'express';
import authControllers from '../controllers/authController.js';

const authRouter = express.Router();

authRouter.route('/register').post(authControllers.register);
authRouter.route('/login').post(authControllers.login);
authRouter.route('/logout').post(authControllers.logout);

export default authRouter;