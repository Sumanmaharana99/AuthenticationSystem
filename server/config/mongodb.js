import mongoose from 'mongoose';
import dotenv from 'dotenv';
dotenv.config();
const URI = process.env.MONGODB_URI; 
const connectDB = async ()=>{
    try {
        mongoose.connection.on('connected', () => {
        console.log('MongoDB connected successfully');
    });
    await mongoose.connect(URI);
    console.log('MongoDB connection established');
    
}
catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1); // Exit the process with failure
  }
}

export default connectDB;