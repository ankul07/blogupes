const crypto = require("crypto");

const mongoose = require("mongoose");

const bcrypt = require("bcryptjs");

const jwt = require("jsonwebtoken");

const UserSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Please provide a username"],
    },
    photo: {
      type: String,
      default: "user.png",
    },
    email: {
      type: String,
      required: [true, "Please provide a email"],
      unique: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please fill a valid email address",
      ],
    },
    password: {
      type: String,
      minlength: [6, "Please provide a password with min length : 6 "],
      required: [true, "Please provide a password"],
      select: false,
    },
    role: {
      type: String,
      default: "user",
      enum: ["user", "admin"],
    },
    readList: [
      {
        type: mongoose.Schema.ObjectId,
        ref: "Story",
      },
    ],
    readListLength: {
      type: Number,
      default: 0,
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }

  const salt = await bcrypt.genSalt(10);

  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.generateJwtFromUser = function () {
  const { JWT_SECRET_KEY, JWT_EXPIRE } = process.env;

  // Check if JWT secret key and expiration are available
  if (!JWT_SECRET_KEY || !JWT_EXPIRE) {
    throw new Error(
      "JWT_SECRET_KEY or JWT_EXPIRE not found in environment variables"
    );
  }

  const payload = {
    id: this._id,
    username: this.username,
    email: this.email,
  };

  try {
    const token = jwt.sign(payload, JWT_SECRET_KEY, { expiresIn: JWT_EXPIRE });
    return token;
  } catch (error) {
    // Handle token generation errors
    console.error("Error generating JWT:", error);
    throw new Error("Error generating JWT");
  }
};

UserSchema.methods.getResetPasswordTokenFromUser = function () {
  const { RESET_PASSWORD_EXPIRE } = process.env;

  const randomHexString = crypto.randomBytes(20).toString("hex");

  const resetPasswordToken = crypto
    .createHash("SHA256")
    .update(randomHexString)
    .digest("hex");

  this.resetPasswordToken = resetPasswordToken;

  this.resetPasswordExpire = Date.now() + parseInt(RESET_PASSWORD_EXPIRE);

  return resetPasswordToken;
};

const User = mongoose.model("User", UserSchema);

module.exports = User;
