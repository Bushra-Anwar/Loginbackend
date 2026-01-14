const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();

/* SIGNUP */
router.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).json({ msg: "Email already exists" });

    const hash = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    await User.create({
      name,
      email,
      password: hash,
      otp,
      otpExpiry: Date.now() + 10 * 60 * 1000,
      isVerified: false
    });

    console.log("OTP:", otp);

    res.json({ msg: "Account created. Verify email" });
  } catch (err) {
    res.status(500).json({ msg: "Signup failed" });
  }
});

/* VERIFY OTP */
router.post("/verify", async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email, otp });
  if (!user || user.otpExpiry < Date.now())
    return res.status(400).json({ msg: "Invalid OTP" });

  user.isVerified = true;
  user.otp = null;
  user.otpExpiry = null;
  await user.save();

  res.json({ msg: "Email verified" });
});

/* LOGIN */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });

  if (!user.isVerified)
    return res.status(401).json({ msg: "Verify email first" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ msg: "Wrong password" });

  const token = jwt.sign({ id: user._id }, "secret123", { expiresIn: "1d" });

  res.json({ token });
});

module.exports = router;
/* FORGOT PASSWORD */
router.post("/forgot", async (req, res) => {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await User.updateOne(
    { email: req.body.email },
    { otp, otpExpiry: Date.now() + 600000 }
  );
  console.log("OTP:", otp);
  res.json({ msg: "OTP sent" });
});

/* RESET PASSWORD */
router.post("/reset", async (req, res) => {
  const user = await User.findOne({
    email: req.body.email,
    otp: req.body.otp
  });

  if (!user || user.otpExpiry < Date.now())
    return res.status(400).json({ msg: "Invalid OTP" });

  user.password = await bcrypt.hash(req.body.password, 10);
  user.otp = null;
  await user.save();

  res.json({ msg: "Password updated" });
});
