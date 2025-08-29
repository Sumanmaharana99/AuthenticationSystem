import jwt from 'jsonwebtoken';

const userAuth = async(req,res,next)=>{
    const {token} = req.cookies;
    if(!token){
        res.status(401).json({success:false, msg: "Unauthorized: No token provided"});
    }
    try{
        const tokenDecode = jwt.verify(token,process.env.JWT_SECRET);
        if(tokenDecode.id){
            req.body.userId =  tokenDecode.id;
        }else{
            return res.status(401).json({success:false, msg: "Unauthorized: Invalid token"});
        }
        next();
    }catch(error){
        res.status(401).json({success:false, msg: "Unauthorized: Invalid token"});
    }
}
export default userAuth;