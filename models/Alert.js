import mongoose from "mongoose";

const alertSchema = new mongoose.Schema({
  logId: { type: mongoose.Schema.Types.ObjectId, ref: "Log", required: true },
  severity: { 
    type: String, 
    enum: ["critical", "high", "medium", "low"], 
    default: "medium" 
  },
  title: { type: String, required: true },
  description: String,
  keywords: [String],
  acknowledged: { type: Boolean, default: false },
  acknowledgedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  acknowledgedAt: Date,
  resolved: { type: Boolean, default: false },
  resolvedAt: Date,
  createdAt: { type: Date, default: Date.now }
});

alertSchema.index({ acknowledged: 1, createdAt: -1 });
alertSchema.index({ severity: 1 });

export default mongoose.model("Alert", alertSchema);