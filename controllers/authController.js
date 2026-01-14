const User = require("../models/User");
const bcrypt = require("bcryptjs");
const generateOTP = require("../utils/generateOTP");
const sendEmail = require("../utils/sendEmail");
const generateToken = require("../utils/generateToken");

/* SIGNUP */
exports.signup = async (req, res) => {
  const { name, email, password } = req.body;

  // already exists
  const exists = await User.findOne({ email });
  if (exists) {
    return res.status(400).json({ msg: "User already exists" });
  }

  // 🔐 ENCRYPT PASSWORD
  const hashedPassword = await bcrypt.hash(password, 10);

  const otp = generateOTP();

  // ✅ SAVE TO MONGODB
  await User.create({
    name,
    email,
    password: hashedPassword,
    otp,
    otpExpire: Date.now() + 5 * 60 * 1000
  });

  await sendEmail(email, "Verify your email", `Your OTP is ${otp}`);

  res.json({ msg: "Account created. Verify email" });
};

/* VERIFY OTP */
exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email });

  if (!user || user.otp !== otp || user.otpExpire < Date.now()) {
    return res.status(400).json({ msg: "Invalid or expired OTP" });
  }

  user.isVerified = true;
  user.otp = null;
  user.otpExpire = null;

  await user.save(); // ✅ UPDATE SAME USER

  res.json({ msg: "Email verified successfully" });
};

/* LOGIN */
exports.login = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ msg: "User not found" });
  }

  if (!user.isVerified) {
    return res.status(401).json({ msg: "Verify email first" });
  }

  // 🔐 COMPARE HASH
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ msg: "Invalid password" });
  }

  const token = generateToken(user._id);
  res.json({ token });
};

/* FORGOT PASSWORD */
exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ msg: "User not found" });

  const otp = generateOTP();

  user.otp = otp;
  user.otpExpire = Date.now() + 5 * 60 * 1000;
  await user.save();

  await sendEmail(email, "Reset Password OTP", otp);
  res.json({ msg: "OTP sent to email" });
};

/* RESET PASSWORD */
exports.resetPassword = async (req, res) => {
  const { email, otp, password } = req.body;

  const user = await User.findOne({ email });

  if (!user || user.otp !== otp || user.otpExpire < Date.now()) {
    return res.status(400).json({ msg: "Invalid OTP" });
  }

  // 🔐 ENCRYPT NEW PASSWORD
  user.password = await bcrypt.hash(password, 10);
  user.otp = null;
  user.otpExpire = null;

  await user.save();

  res.json({ msg: "Password reset successful" });
};
