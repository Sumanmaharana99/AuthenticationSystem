import express from 'express';
import userAuth from '../middleware/userAuth.js';
import userController from '../controllers/userController.js';
const userRouter = express.Router();
userRouter.route('/data').get(userAuth,userController.getUserData);
export default userRouter;