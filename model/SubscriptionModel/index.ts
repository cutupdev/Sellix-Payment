import { required } from "joi";
import mongoose, { Schema } from "mongoose";

const SubscriptionSchema = new mongoose.Schema({
  userId: { type: Schema.Types.ObjectId, required: true },
  serviceId: { type: Schema.Types.ObjectId, required: true },
  status: { type: String, required: true },
  customName: { type: String },
  startDate: { type: Date },
  expireDate: { type: Date, required: true },
  createdAt: { type: Date },
  updatedAt: { type: Date }
});

const SubscriptionModel = mongoose.model("subscription", SubscriptionSchema);

export default SubscriptionModel;
