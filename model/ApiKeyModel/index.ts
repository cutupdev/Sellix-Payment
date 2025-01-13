import mongoose, { Schema } from "mongoose";

const ApiKeySchema = new mongoose.Schema({
  subscriptionId: { type: Schema.Types.ObjectId, required: true },
  apiKey: { type: String, required: true, unique: true },
});

const ApiKeyModel = mongoose.model("apikey", ApiKeySchema);

export default ApiKeyModel;
