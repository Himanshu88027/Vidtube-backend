import { asyncHandler } from "../utils/asynHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinaryService.js";

const generateAccessAndRefreshToken = async (user_id) => {
    const user = await User.findById(user_id);

    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({validateBeforesave: false});

    return { accessToken, refreshToken }
}

const userRegister = asyncHandler(async (req, res) => {
    const {fullName, username, email, password} = req.body

    if (
        [fullName, username, email, password].some((field)=>(field?.trim() == ""))
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
        coverImage: coverImage?.url || "",
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

    const { accessToken, refreshToken } = generateAccessAndRefreshToken(user._id);

    const loggedUser = User.findById(user._id).select(
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
export { userRegister }