import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import startServer from "./db.js";
import { register, login, getMe, getAll } from "./controllers/auth.js";
import { checkAuth } from "./middleware/checkAuth.js";

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());

app.post("/auth/register", register);
app.post("/auth/login", login);
app.get("/auth/me", checkAuth, getMe);
app.get("/auth/getAll", getAll);

startServer(app);
