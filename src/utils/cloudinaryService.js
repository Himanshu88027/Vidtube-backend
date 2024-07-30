import { v2 as cloudinary } from 'cloudinary';
import fs from "fs";
cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET
});


const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return null;
        const uploadResult = await cloudinary.uploader.upload(localFilePath,{
            resource_type: "auto"
        })
        // console.log("file is uploaded succesfully on cloudinary",uploadResult.url);
        fs.unlinkSync(localFilePath)
        return uploadResult;
    } catch (error) {
        fs.unlinkSync(localFilePath)
        console.log(error);
        return null;
    }
}

const deleteOnCloudinary = async(avatarId) => {
    try {
        if (!avatarId) return null;
        await cloudinary.uploader.destroy(avatarId);
        return true;
    } catch (error) {
        console.log(error);
        return false;
    }
}

export { uploadOnCloudinary, deleteOnCloudinary };