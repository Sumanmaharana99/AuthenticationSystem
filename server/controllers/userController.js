import userModel from "../models/userModel.js";
export const getUserData = async (req, res) => {
   try {
       const{userId} = req.body;
       const user = await userModel.findById(userId);
       if(!user){
        return res.status(404).json({success: false, msg: "User not found"});
       }
       res.status(200).json({success: true, userData: {
         name: user.name,
         isAccountVerified: user.isVerified,

       }});
   } catch (error) {
    res.status(500).json({success: false, msg: "Error in get user data controller", error: error.message});
    console.log(error.message);
   }
}
export default {getUserData};