const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets");
const Users = require("../users/users-model");
const jwt = require("jsonwebtoken");

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req;

  const hash = bcrypt.hashSync(password, 8);

  Users.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { user } = req;
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    const tokenBuilder = (userInfo) => {
      const payload = {
        subject: userInfo.user_id,
        username: userInfo.username,
        role_name: userInfo.role_name,
      };
      const options = {
        expiresIn: "1d",
      };
      return jwt.sign(payload, JWT_SECRET, options);
    };
    const token = tokenBuilder(user);
    res.status(200).json({ message: `${user.username} is back!`, token });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
});

module.exports = router;
