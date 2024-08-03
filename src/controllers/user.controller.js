import { asyncHandler } from "../utils/asynHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from "../models/user.model.js";
import { deleteOnCloudinary, uploadOnCloudinary } from "../utils/cloudinaryService.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const generateAccessAndRefreshToken = async (user_id) => {
    try {
        const user = await User.findById(user_id);

        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforesave: false });

        return { accessToken, refreshToken }
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating referesh and access token")
    }
}

const userRegister = asyncHandler(async (req, res) => {
    const { fullName, username, email, password } = req.body

    if (
        [fullName, username, email, password].some((field) => (field?.trim() == ""))
    ) {
        throw new ApiError(400, "Please enter all valid fields")
    }

    const existedUser = await User.findOne(
        { $or: [{ username }, { email }] }
    )

    if (existedUser) {
        throw new ApiError(400, "Username or email already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;
    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        username: username.toLowerCase(),
        email,
        password,
        avatar: avatar.url,
        avatarPublicId: avatar.public_id,
        coverImage: coverImage?.url || "",
        coverImagePublicId: coverImage?.public_id || "",
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(200).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
})

const login = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if (!username && !email) {
        throw new ApiError(400, "Please enter username or email")
    }

    const user = await User.findOne({
        $or: [{ username }, { email }],
    });

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    const isPasswordValid = await user.comparePassword(password)

    if (!isPasswordValid) {
        throw new ApiError(400, "Incorrect password")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id);

    const loggedUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200,
                {
                    user: loggedUser, accessToken, refreshToken
                },
                "User logged in successfully"
            )
        )
})

const logout = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, {
        $unset: {
            refreshToken: 1
        }
    },
        {
            new: true
        })

    const options = {
        httpOnly: true,
        secure: true
    }

    res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, "Refresh token is required")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        if (!decodedToken) {
            throw new ApiError(401, "Invalid refresh token")
        }

        const user = await User.findById(decodedToken?._id)

        if (!user || user.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Invalid refresh token")
        }

        const { accessToken, newRefreshToken } = generateAccessAndRefreshToken(user._id);

        const options = {
            httpOnly: true,
            secure: true
        }

        res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(200,
                    { accessToken, newRefreshToken },
                    "Access token refreshed successfully"
                )
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

const forgotPassword = asyncHandler(async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
        throw new ApiError(400, "Please enter current password and new password")
    }

    const user = await User.findById(req.user._id);

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    const isPasswordValid = await user.comparePassword(currentPassword)

    if (!isPasswordValid) {
        throw new ApiError(400, "Incorrect current password")
    }

    user.password = newPassword;
    await user.save({ validateBeforesave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, "Password updated successfully")
        )
})

const getCurrentUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select(
        "-password -refreshToken"
    )

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    return res
        .status(200)
        .json(
            new ApiResponse(200, user, "User details")
        )
})

const updateUser = asyncHandler(async (req, res) => {
    const { email, fullName } = req.body;

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(req.user._id, {
        $set: {
            fullName,
            email
        }
    },
        {
            new: true
        }).select(
            "-password"
        )

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }
    console.log(req.user._id);
    const user = await User.findById(req.user._id)

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    const deleteAvatar = await deleteOnCloudinary(user.avatarPublicId)
    console.log("deleteAvatar :", deleteAvatar);
    if (!deleteAvatar) {
        throw new ApiError(500, "Failed to delete the old avatar image")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const newUpdatedUser = await User.findByIdAndUpdate(req.user?._id, {
        $set: {
            avatar: avatar.url,
            avatarPublicId: avatar.public_id
        }
    },
        {
            new: true
        }).select(
            "-password"
        )

    return res
        .status(200)
        .json(
            new ApiResponse(200, newUpdatedUser, "Avatar image updated successfully")
        )

})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }
    console.log(req.user._id);
    const user = await User.findById(req.user._id)

    if (!user) {
        throw new ApiError(400, "User doesn't exists")
    }

    const deleteCoverImage = await deleteOnCloudinary(user.coverImagePublicId)
    // console.log("deletecoverImage :", deletecoverImage);
    if (!deleteCoverImage) {
        throw new ApiError(500, "Failed to delete the old coverImage image")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage) {
        throw new ApiError(400, "coverImage file is required")
    }

    const newUpdatedUser = await User.findByIdAndUpdate(req.user?._id, {
        $set: {
            coverImage: coverImage.url,
            coverImagePublicId: coverImage.public_id
        }
    },
        {
            new: true
        }).select(
            "-password"
        )

    return res
        .status(200)
        .json(
            new ApiResponse(200, newUpdatedUser, "Avatar image updated successfully")
        )

})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params;

    if (!username?.trim()) {
        throw new ApiError(400, "Username is required")
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            }
        },
        {
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            }
        },
        {
            $lookup:{
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscriberTo"
            }
        },
        {
           $addFields:{
                subscribersCount :{
                    $size: "$subscribers"
                },
                channelsSubscribersToCount: {
                    $size: "$subscriberTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {$in: [req.user?._id, "$subscribers.subscriber"]},
                        then: true,
                        else: false
                    }
                }
           }
        },
        {
            $project: {
                username: 1,
                fullName: 1,
                email: 1,
                avatar: 1,
                coverImage: 1,
                subscribersCount: 1,
                channelsSubscribersToCount: 1,
                isSubscribed: 1
            }
        }

    ])

    if (!channel?.length) {
        throw new ApiError(404, "User not found")
    }

    return res
       .status(200)
       .json(
            new ApiResponse(200, channel[0], "User channel profile")
        )

})

const getWatchHistory = asyncHandler(async(req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id),
            }
        },
        {
            $lookup: {
                from: "videos",
                localField: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project:{
                                        username: 1,
                                        fullName: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        },
        {
            $addFields:{
                owner:{
                    $first: "$owner"
                }
            }
        }
    ])

    if (!user?.length) {
        throw new ApiError(404, "User not found")
    }
    
    return res
    .status(200)
    .json(
        new ApiResponse(200, user[0].watchHistory, "User watch history")
    )
})

export { 
    userRegister, 
    login, 
    logout, 
    refreshAccessToken, 
    forgotPassword, 
    getCurrentUser, 
    updateUser, 
    updateUserAvatar, 
    updateUserCoverImage, 
    getUserChannelProfile, 
    getWatchHistory 
}