import { required } from "joi";
import mongoose, { Schema } from "mongoose";

const UserSchema = new mongoose.Schema({
  username: { type: String },
  email: { type: String, sparse: true },
  password: { type: String },
  verified: { type: Boolean, required: true, default: false },
  discordId: { type: String },
  googleId: { type: String },
  wallet: { type: String },
  role: { type: Number, default: 0 },
  account: { type: Number, required: true }
});

const UserModel = mongoose.model("user", UserSchema);

export default UserModel;




