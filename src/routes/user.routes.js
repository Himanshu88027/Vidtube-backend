import { Router } from "express";
import { login, logout, updateUserAvatar, userRegister } from "../controllers/user.controller.js";
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
router.route("/avatar").post( jwtVerify, upload.single("avatar"), updateUserAvatar)

export default router;