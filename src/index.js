import dotenv from "dotenv"
import connectDB from "./db/index.js"

// Load environment variables from .env file

dotenv.config({
    path: "./env"
})

connectDB();