import { required } from "joi";
import mongoose from "mongoose";

const ServiceSchema = new mongoose.Schema({
  serviceName: { type: String, required: true, },
  tierName: { type: String, required: true },
  description: { type: String },
  connectionURL: { type: String },
  dailyPrice: { type: Number },
  weeklyPrice: { type: Number },
  monthlyPrice: { type: Number },
});

const ServiceModel = mongoose.model("service", ServiceSchema);

export default ServiceModel;
