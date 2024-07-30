import jwt from "jsonwebtoken"
import { asyncHandler } from "../utils/asynHandler"
import { User } from "../models/user.model"

export const jwtVerify = asyncHandler ( async (req, _, next) => {
    const token = req.cookies?.accessToken || req.headers.authorization?.split(' ')[1]

    if (!token) {
        throw new ApiError(400, "Access denied. No token provided")
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)

    const user = User.findById(decodedToken?._id).select(
        "-password -refreshToken"
    )

    if (!user) {
        throw new ApiError(400, "Access denied. Invalid token")
    }

    req.user = user
    next()
})