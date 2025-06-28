const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");

const {
  User,
  validateRegisterUser,
  validateLoginUser,
} = require("../models/User");
const VerificationToken = require("../models/VerificationToken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
// const jwt = require("jsonwebtoken");
/**-----------------------------------------------
 * @desc    Register New User
 * @route   /api/auth/register
 * @method  POST
 * @access  public
 ------------------------------------------------*/
module.exports.registerUserCtrl = asyncHandler(async (req, res) => {
  // validation
  const { error } = validateRegisterUser(req.body);
  if (error) {
    return res.status(400).json(error.details[0]);
  }

  // Check if user already exists
  let user = await User.findOne({ email: req.body.email });
  if (user) {
    return res.status(400).json({ message: "user already exist" });
  }

  // hashing the password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // Creating new User & save it toDB
  user = new User({
    firstname: req.body.firstname,
    lastname: req.body.lastname,
    phonenumber: req.body.phonenumber,
    email: req.body.email,
    password: hashedPassword,
  });
  await user.save();

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Creating new VerificationToken & save it toDB
  const verifictionToken = new VerificationToken({
    userId: user._id,
    token: crypto.randomBytes(32).toString("hex"),
    // otp: otp,
  });
  await verifictionToken.save();

  const htmlTemplate = `
  <div style="font-family: Arial, sans-serif; line-height:1.5;">
    <h2>Hello ${req.body.firstname + " " + req.body.lastname || ""} 👋,</h2>
    <p>Here is your verification code:</p>
    <p style="font-size: 24px; font-weight: bold;">${otp}</p>
    <p>This code is valid for 10 minutes.</p>
  </div>
`;

  await sendEmail(user.email, "Your OTP Code", htmlTemplate);
  res.status(201).json({
    message: "Check your email for OTP to verify your account",
    userId: user._id,
    token: verifictionToken.token,
    otp: otp,
  });
});
/**-----------------------------------------------
 * @desc    Verify OTP
 * @route   /api/auth/verifyOTP
 * @method  GET
 * @access  public
 ------------------------------------------------*/
module.exports.verifyOtpUserAccountCtrl = asyncHandler(async (req, res) => {
  const { otp, email } = req.body;

  // Validate OTP format: must be exactly 6 digits
  const otpPattern = /^\d{6}$/;
  if (!otpPattern.test(otp)) {
    return res
      .status(400)
      .json({ message: "Invalid OTP format. Must be 6 digits." });
  }

  // Find user by email (not by user.email, which was undefined)
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: "User not found." });
  }

  // Find verification token associated with this user and OTP
  const verificationToken = await VerificationToken.findOne({
    userId: user._id,
  });
  if (!verificationToken) {
    return res.status(400).json({ message: "Invalid OTP or token." });
  }
  const truOTp = await compare(otp, verificationToken.otp);
  if (!truOTp) {
    return res.status(400).json({ message: "Invalid OTP ." });
  }
  // Mark user as verified
  user.isAccountVerified = true;
  user.otp = otp;
  await user.save();

  // Remove the used verification token
  await verificationToken.deleteOne();

  return res
    .status(200)
    .json({ message: "Your account has been verified successfully." });
});

/**-----------------------------------------------
 * @desc    send  OTP
 * @route   /api/auth/verifyOTP
 * @method  GET
 * @access  public
 ------------------------------------------------*/

module.exports.sendOTP = asyncHandler(async (req, res) => {
  const { email, name } = req.body;

  /* ---------- 1. Validation ---------- */
  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required" });
  }
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res
      .status(400)
      .json({ success: false, message: "User already exists" });
  }

  /* ---------- 2. Génération de l’OTP ---------- */
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  /* ---------- 3. Envoi de l’e‑mail ---------- */
  const htmlTemplate = `
    <div style="font-family: Arial, sans-serif; line-height:1.5;">
      <h2>Bonjour ${name || ""} 👋,</h2>
      <p>Voici votre code de vérification :</p>
      <p style="font-size: 24px; font-weight: bold;">${otp}</p>
      <p>Ce code est valable 10 minutes.</p>
    </div>
  `;
  await sendEmail(email, "Your OTP Code", htmlTemplate);

  /* ---------- 4. Réponse ---------- */
  return res.status(200).json({
    success: true,
    message: "OTP sent! Check your email.",
  });
});

/**-----------------------------------------------
 * @desc    Login User
 * @route   /api/auth/login
 * @method  POST
 * @access  public
 ------------------------------------------------*/
module.exports.loginUserCtrl = asyncHandler(async (req, res) => {
  // 1. Validate input data
  const { error } = validateLoginUser(req.body);
  if (error) {
    return res.status(400).json({ message: error.details[0].message });
  }

  // 2. Check if user exists by email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    // Avoid leaking which part is incorrect for security
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // 3. Verify password match
  const isPasswordMatch = await bcrypt.compare(
    req.body.password,
    user.password
  );
  if (!isPasswordMatch) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // 4. Check if user email is verified
  if (!user.isAccountVerified) {
    // Check if there’s an existing verification token
    let verificationToken = await VerificationToken.findOne({
      userId: user._id,
    });

    if (!verificationToken) {
      // Create new verification token and save
      verificationToken = new VerificationToken({
        userId: user._id,
        token: crypto.randomBytes(32).toString("hex"),
      });
      await verificationToken.save();
    }

    return res.status(403).json({
      message:
        "Your account is not verified. Please check your email to verify your account.",
    });
  }

  // 5. Generate authentication token (e.g., JWT)
  const token = user.generateAuthToken();

  // 6. Respond with user info and token
  res.status(200).json({
    message: "Login successful",
    // user: {
    //   _id: user._id,
    //   firstname: user.firstname,
    //   lastname: user.lastname,
    //   phonenumber: user.phonenumber,
    //   email: user.email,
    //   coins: 100
    // },
    token,
  });
});

/**-----------------------------------------------
 * @desc    Verify User Account
 * @route   /api/auth/:userId/verify/:token
 * @method  GET
 * @access  public
 ------------------------------------------------*/
module.exports.verifyUserAccountCtrl = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.userId);

  if (!user) {
    return res.status(400).json({ message: "invalid link" });
  }

  const verificationToken = await VerificationToken.findOne({
    userId: user._id,
    token: req.params.token,
  });

  if (!verificationToken) {
    return res.status(400).json({ message: "invalid link" });
  }

  user.isAccountVerified = true;
  await user.save();

  await verificationToken.remove();

  res.status(200).json({ message: "Your account verified" });
});

/**-----------------------------------------------
 * @desc    Send OTP verification email with OTP
 * @route   /api/auth/:userId/:otp/send
 * @method  GET
 * @access  public
 ------------------------------------------------*/

module.exports.sendOtpVerificationEmailCtrl = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.userId);
  if (!user) {
    return res.status(400).json({ message: "invalid user" });
  }

  const verificationToken = await VerificationToken.findOne({
    userId: user._id,
  });

  if (!verificationToken) {
    return res.status(400).json({ message: "invalid token" });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Save OTP to the verification token
  verificationToken.otp = otp;
  await verificationToken.save();

  // Send OTP via email
  const htmlTemplate = `
    <div>
      <p>Your OTP is: <strong>${otp}</strong></p>
      <p>Please use this OTP to verify your account.</p>
    </div>`;

  await sendEmail(user.email, "Your OTP Code", htmlTemplate);

  res.status(200).json({
    message: "OTP sent to your email",
    userId: user._id,
    token: verificationToken.token,
    otp: otp,
  });
});

module.exports.saveDataFromAppCtrl = asyncHandler(async (req, res) => {
  try {
    const users = req.body.users;
    const createdUsers = [];

    for (const userData of users) {
      const exists = await User.findOne({ email: userData.email });
      if (exists) continue;

      const user = new User({
        firstname: userData.firstname,
        lastname: userData.firstname,
        phonenumber: userData.phonenumber,
        email: userData.email,
        password: userData.password, // already hashed
        isAccountVerified: true,
        ID_from_app: userData.ID_from_app,
      });

      await user.save();

      const verificationToken = new VerificationToken({
        userId: user._id,
        token: crypto.randomBytes(32).toString("hex"),
      });

      await verificationToken.save();
      createdUsers.push(user._id);
    }

    return res.status(201).json({
      message: "Users saved successfully",
      createdUsers,
    });
  } catch (err) {
    return res.status(500).json({
      message: "Error saving users",
      error: err.message,
    });
  }
});
