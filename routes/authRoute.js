const router = require("express").Router();

const { registerUserCtrl, loginUserCtrl, verifyUserAccountCtrl, verifyOtpUserAccountCtrl,sendOTP,saveDataFromAppCtrl } = require("../controllers/authController")
// const {
//   verifyTokenAndAdmin,
//   verifyTokenAndOnlyUser,
//   verifyToken,
//   verifyTokenAndAuthorization,
// } = require("../middlewares/verifyToken");
// /api/auth/register
router.post("/register", registerUserCtrl);
// vefy user account with OTP
router.post("/saveData", saveDataFromAppCtrl);


router.post("/", );

// /api/auth/login
router.post("/login", loginUserCtrl);

// /api/auth/veryfy
router.post("/sendOtp", sendOTP);
// router.post("/register", sendOTP);

// /api/users/profile
// router.route("/profile").get(verifyTokenAndAdmin, getAllUsersCtrl);


module.exports = router;