const asyncHandler = require("express-async-handler");
const {
  User,
  validateRegisterUser,
  validateLoginUser,
} = require("../models/User");
const verifyJWT = require("../middlewares/verifyJWT");

/**-----------------------------------------------
 * @desc    Register New User
 * @route   /api/auth/register
 * @method  POST
 * @access  public
 ------------------------------------------------*/
 module.exports.checkLogin = asyncHandler(async (req, res) => {
  const { error } = validateRegisterUser(req.body);
 }
);