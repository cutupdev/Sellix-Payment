import mongoose, { Schema } from "mongoose";

const ProxySchema = new mongoose.Schema({
  serviceId: { type: Schema.Types.ObjectId, required: true },
  ipAddress: { type: String, required: true },
});

const ProxyModel = mongoose.model("proxy", ProxySchema);

export default ProxyModel;
