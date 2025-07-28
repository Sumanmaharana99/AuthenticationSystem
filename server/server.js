import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import 'dotenv/config';

const app = express();
const port = process.env.PORT || 4000;
app.use(express.json());
app.use(cookieParser());
app.use(cors({credentials: true}));

app.get('/', (req, res) => {
  res.send('Hello World!'); 
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});