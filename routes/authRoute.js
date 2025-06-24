const router = require("express").Router();

const { registerUserCtrl, loginUserCtrl, verifyUserAccountCtrl, verifyOtpUserAccountCtrl,sendOTP } = require("../controllers/authController")
// const {
//   verifyTokenAndAdmin,
//   verifyTokenAndOnlyUser,
//   verifyToken,
//   verifyTokenAndAuthorization,
// } = require("../middlewares/verifyToken");

// /api/auth/register
router.post("/register", registerUserCtrl);
// vefy user account with OTP
router.post("/verify-otp", verifyOtpUserAccountCtrl);

// /api/auth/login
router.post("/login", loginUserCtrl);

// /api/auth/veryfy
router.post("/sendOtp", sendOTP);
// router.post("/register", sendOTP);


// // /api/users/profile
// router.route("/profile").get(verifyTokenAndAdmin, getAllUsersCtrl);

module.exports = router;