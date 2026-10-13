import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: ["admin", "user"], default: "user" },
  active: { type: Boolean, default: true }
}, { timestamps: true });

const entrySchema = new mongoose.Schema({
  type: { type: String, enum: ["sale", "purchase"], required: true },
  token: { type: String, required: true, trim: true, maxlength: 100 },
  quantity: { type: Number, required: true, min: 0.0001 },
  rate: { type: Number, required: true, min: 0 },
  date: { type: Date, required: true },
  notes: { type: String, trim: true, maxlength: 500, default: "" },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
}, { timestamps: true });

entrySchema.index({ date: -1 });
entrySchema.index({ createdBy: 1, date: -1 });

export const User = mongoose.model("User", userSchema);
export const Entry = mongoose.model("Entry", entrySchema);
