import "dotenv/config";
import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User, Entry } from "./models.js";

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const allowedOrigins = (process.env.FRONTEND_ORIGIN || "http://localhost:5173")
  .split(",").map(x => x.trim().replace(/\/$/, "")).filter(Boolean);

if (!process.env.MONGODB_URI || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Configuration error: set MONGODB_URI and JWT_SECRET (32+ characters) in server/.env.");
  process.exit(1);
}

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  }
}));
app.use(express.json({ limit: "1mb" }));

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const publicUser = user => ({ id: user._id, name: user.name, email: user.email, role: user.role, active: user.active });

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "8h" });
}

const auth = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Please sign in." });
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ message: "Session expired. Please sign in again." }); }
  const user = await User.findById(payload.sub);
  if (!user || !user.active) return res.status(401).json({ message: "Account unavailable." });
  req.user = user;
  next();
});

const adminOnly = (req, res, next) => {
  if (req.user?.role !== "admin") return res.status(403).json({ message: "Admin permission required." });
  next();
};

app.get("/api/health", (req, res) => res.json({
  ok: true, service: "token-tracker-api",
  db: mongoose.connection.readyState === 1 ? "connected" : "disconnected"
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
  const user = await User.findOne({ email }).select("+passwordHash");
  if (!user || !user.active || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: "Invalid email or password." });
  }
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post("/api/auth/change-password", auth, asyncRoute(async (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const user = await User.findById(req.user._id).select("+passwordHash");
  if (!currentPassword || !(await bcrypt.compare(currentPassword, user.passwordHash))) {
    return res.status(400).json({ message: "Current password is incorrect." });
  }
  if (newPassword.length < 10) return res.status(400).json({ message: "New password must be at least 10 characters." });
  user.passwordHash = await bcrypt.hash(newPassword, 12);
  await user.save();
  res.json({ message: "Password updated. Sign in again if your session expires." });
}));

// Admin user management
app.get("/api/users", auth, adminOnly, asyncRoute(async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json({ users: users.map(publicUser) });
}));

app.post("/api/users", auth, adminOnly, asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const role = req.body.role === "admin" ? "admin" : "user";
  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Enter a valid name and email." });
  if (password.length < 10) return res.status(400).json({ message: "Password must be at least 10 characters." });
  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ message: "An account with that email already exists." });
  const user = await User.create({ name, email, role, passwordHash: await bcrypt.hash(password, 12) });
  res.status(201).json({ user: publicUser(user) });
}));

app.patch("/api/users/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found." });
  if (user._id.equals(req.user._id) && req.body.active === false) return res.status(400).json({ message: "You cannot deactivate your own account." });
  if (typeof req.body.name === "string" && req.body.name.trim()) user.name = req.body.name.trim();
  if (["admin", "user"].includes(req.body.role)) user.role = req.body.role;
  if (typeof req.body.active === "boolean") user.active = req.body.active;
  await user.save();
  res.json({ user: publicUser(user) });
}));

app.delete("/api/users/:id", auth, adminOnly, asyncRoute(async (req, res) => {
  if (req.params.id === req.user._id.toString()) return res.status(400).json({ message: "You cannot delete your own account." });
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found." });
  res.json({ message: "User deleted." });
}));

// Ledger entries: admins can see all; users only see their own.
app.get("/api/entries", auth, asyncRoute(async (req, res) => {
  const filter = req.user.role === "admin" ? {} : { createdBy: req.user._id };
  if (["sale", "purchase"].includes(req.query.type)) filter.type = req.query.type;
  const entries = await Entry.find(filter).populate("createdBy", "name email").sort({ date: -1, createdAt: -1 }).limit(2000);
  res.json({ entries });
}));

app.post("/api/entries", auth, asyncRoute(async (req, res) => {
  const type = req.body.type;
  const token = String(req.body.token || "").trim();
  const quantity = Number(req.body.quantity);
  const rate = Number(req.body.rate);
  const date = new Date(req.body.date);
  const notes = String(req.body.notes || "").trim();
  if (!["sale", "purchase"].includes(type)) return res.status(400).json({ message: "Type must be sale or purchase." });
  if (!token || token.length > 100) return res.status(400).json({ message: "Enter a token/product name." });
  if (!Number.isFinite(quantity) || quantity <= 0 || !Number.isFinite(rate) || rate < 0) return res.status(400).json({ message: "Quantity must be positive and rate cannot be negative." });
  if (!req.body.date || Number.isNaN(date.getTime())) return res.status(400).json({ message: "Enter a valid date." });
  const entry = await Entry.create({ type, token, quantity, rate, date, notes, createdBy: req.user._id });
  await entry.populate("createdBy", "name email");
  res.status(201).json({ entry });
}));

app.delete("/api/entries/:id", auth, asyncRoute(async (req, res) => {
  const entry = await Entry.findById(req.params.id);
  if (!entry) return res.status(404).json({ message: "Entry not found." });
  if (req.user.role !== "admin" && !entry.createdBy.equals(req.user._id)) return res.status(403).json({ message: "You can only delete your own entries." });
  await entry.deleteOne();
  res.json({ message: "Entry deleted." });
}));

app.get("/api/reports/summary", auth, asyncRoute(async (req, res) => {
  const match = req.user.role === "admin" ? {} : { createdBy: req.user._id };
  const rows = await Entry.aggregate([
    { $match: match },
    { $group: { _id: "$type", quantity: { $sum: "$quantity" }, amount: { $sum: { $multiply: ["$quantity", "$rate"] } }, count: { $sum: 1 } } }
  ]);
  const summary = { sales: { quantity: 0, amount: 0, count: 0 }, purchases: { quantity: 0, amount: 0, count: 0 } };
  for (const row of rows) summary[row._id === "sale" ? "sales" : "purchases"] = { quantity: row.quantity, amount: row.amount, count: row.count };
  summary.net = summary.sales.amount - summary.purchases.amount;
  summary.users = req.user.role === "admin" ? await User.countDocuments() : undefined;
  res.json({ summary });
}));

app.use((err, req, res, next) => {
  if (err?.message?.startsWith("CORS blocked origin:")) return res.status(403).json({ message: err.message });
  if (err?.code === 11000) return res.status(409).json({ message: "That email already exists." });
  if (err?.name === "ValidationError") return res.status(400).json({ message: err.message });
  console.error(err);
  res.status(500).json({ message: "Unexpected server error." });
});

async function start() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("MongoDB connected");
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || "");
  if (email && password) {
    const exists = await User.findOne({ email });
    if (!exists) {
      await User.create({
        name: process.env.ADMIN_NAME || "Administrator",
        email,
        role: "admin",
        passwordHash: await bcrypt.hash(password, 12)
      });
      console.log(`Initial admin created for ${email}`);
    }
  } else {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD not set; create an admin before production use.");
  }
  app.listen(PORT, () => console.log(`Token Tracker API listening on port ${PORT}`));
}
start().catch(err => { console.error("Startup failed:", err.message); process.exit(1); });
