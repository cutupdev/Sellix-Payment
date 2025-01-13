import mongoose, { Schema } from "mongoose";

const PaymentSchema = new mongoose.Schema({
  userId: { type: Schema.Types.ObjectId, required: true },
  subscriptionId: { type: Schema.Types.ObjectId, required: true },
  paymentAmount: { type: Number, required: true },
  paymentDate: { type: Date, required: true },
  paymentMethod: { type: String },
  transactionId: { type: String },
});

const PaymentModel = mongoose.model("payment", PaymentSchema);

export default PaymentModel;