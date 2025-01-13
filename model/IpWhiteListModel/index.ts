import { required } from "joi";
import mongoose, { Schema } from "mongoose";

const IpWhiteListSchema = new mongoose.Schema({
  subscriptionId: { type: Schema.Types.ObjectId, required: true },
  ip: { type: String, required: true },
});

const IpWhiteListModel = mongoose.model("ipwhitelist", IpWhiteListSchema);

export default IpWhiteListModel;
