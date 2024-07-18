require("dotenv").config();
import mongoose, { Document, Schema, Model } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { promises } from "dns";

const emailRegexPattern: RegExp = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export interface IUser extends Document {
    name: string;
    email: string;
    password: string;
    createdAt: Date;
    updatedAt: Date;
    avatar: {
        public_id: string;
        url: string;
    }
    role: string;
    isVerified: boolean;
    courses: Array<{courseId: string}>;
    comparePassword(password: string): Promise<boolean>;
    SignAccessToken: () => string;
    SignRefreshToken: () => string;

};

const userSchema: Schema<IUser> = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name is required"],
        minlength: [3, "Name must be at least 3 characters long"],
        maxlength: [50, "Name must be less than 50 characters long"],
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        validate: {
            validator: function (email: string) {
                return emailRegexPattern.test(email);
        },
        message: "Email is invalid",
    },

    unique: true},

    password: {
        type: String,
        // required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters long"],
        select: false,
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
    avatar: {
        public_id: String,
        url: String,
            
        },

    role: {
        type: String,
        default: "user",
    },

    isVerified: {
        type: Boolean,
        default: false,
    },

    courses: [
        {
        courseId: String,
        }
    ],

}, {timestamps: true});


// hash password before saving to database
userSchema.pre<IUser>("save", async function (next) {
    if (!this.isModified("password")) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    // console.log("Hashed Password Before Save:", this.password);
    next();
});


// sign access token
userSchema.methods.SignAccessToken = function () {
    const token = jwt.sign({ _id: this._id }, process.env.ACCESS_TOKEN as string || "", {
        expiresIn: "5m",
    });
    return token;
};


// sign refresh token
userSchema.methods.SignRefreshToken = function () {
    const token = jwt.sign({ _id: this._id }, process.env.REFRESH_TOKEN as string || "", {
        expiresIn: "7d",
    });
    return token;
};

// Compare Password
    userSchema.methods.comparePassword = async function (enteredPassword: string) {
        // console.log("Entered Password:", enteredPassword);
        // console.log("Stored Hashed Password:", this.password);
        const result = await bcrypt.compare(enteredPassword, this.password);
        // console.log("Password Comparison Result:", result);
        return result;
    };
    


const userModel: Model<IUser> =  mongoose.model("User", userSchema); 
export default userModel;





