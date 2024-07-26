import express from "express";
import cookieParser from "cookie-parser";
import cors from 'cors'

const app = express();

// Middleware
app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
}))
app.use(express.json({limit: "10kb"}));
app.use(express.urlencoded({extended: true, limit: "10kb"}));
app.use(express.static("public"))
app.use(cookieParser())


//import routes
import userRoutes from './routes/user.routes.js';
//declare user routes
app.use('/users', userRoutes);

export { app }
