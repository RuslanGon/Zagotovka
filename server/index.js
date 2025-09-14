import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors'
import startServer from './db.js';
import { getMe, login, register } from './controllers/auth.js';
import { checkAuth } from './middleware/checkAuth.js';

dotenv.config(); 


const app = express();

app.use(cors())

app.use(express.json())

app.post("/auth/login", login);
app.post('auth/register', register)
app.get('auth/me',checkAuth, getMe)



startServer(app);