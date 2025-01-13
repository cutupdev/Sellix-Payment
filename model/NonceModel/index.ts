import mongoose from "mongoose";

const NonceSchema = new mongoose.Schema({
    wallet: {
        required: true,
        type: String
    },
    createdAt: {
        type: Date,
        expire: 1200,      //  300
        default: Date.now()
    },
    nonce: {
        type: String,
        required: true
    },
    authorized: {
        type: Boolean,
        default: false
    }
})

const NonceModel = mongoose.model("nonce", NonceSchema);

export default NonceModel;