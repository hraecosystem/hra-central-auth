const router = require("express").Router();
const { checkLogin } = require("../controllers/authCheckController")

// /api/auth/auth-check
router.get("/auth-check", checkLogin);

// router.get("/me", verifyJWT, async (req, res) => {
//   const user = await User.findById(req.user._id).select("-password");
//   res.json(user);
// });

module.exports = router;