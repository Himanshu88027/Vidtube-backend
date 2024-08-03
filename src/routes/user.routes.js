import { Router } from "express";
import { forgotPassword, getCurrentUser, getUserChannelProfile, getWatchHistory, login, logout, refreshAccessToken, updateUser, updateUserAvatar, updateUserCoverImage, userRegister } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { jwtVerify } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount: 1
        }, 
        {
            name: "coverImage",
            maxCount: 1
        }
    ]),
    userRegister
)

router.route("/login").post(login)

// secure routes
router.route("/logout").post(jwtVerify, logout)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/forgot-password").post(jwtVerify, forgotPassword)
router.route("/current-user").get(jwtVerify, getCurrentUser)
router.route("/update-user").patch(jwtVerify, updateUser)

router.route("/avatar").patch( jwtVerify, upload.single("avatar"), updateUserAvatar)
router.route("/cover-image").patch( jwtVerify, upload.single("coverImage"), updateUserCoverImage)

router.route("/channel/:username").get(getUserChannelProfile)
router.route("/history").get(jwtVerify, getWatchHistory)

export default router;