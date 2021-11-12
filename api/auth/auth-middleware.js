const { JWT_SECRET } = require("../secrets");
const jwt = require("jsonwebtoken");
const { findBy } = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return next({ status: 401, message: "Token required" });
  }
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return next({
        status: 401,
        message: "Token invalid",
      });
    } else {
      req.decoded = decoded;
      next();
    }
  });
};

const only = (role_name) => (req, res, next) => {
  if (req.decoded.role_name !== role_name) {
    next({ status: 403, message: "This is not for you" });
  } else {
    next();
  }
};

const checkUsernameExists = (req, res, next) => {
  const { username } = req.body;
  findBy({ username })
    .then((user) => {
      if (!user) {
        next({ status: 401, message: "Invalid credentials" });
      } else {
        req.user = user[0];
        next();
      }
    })
    .catch(next);
};

const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || role_name.trim() === "") {
    req.role_name = "student";
    next();
  } else if (role_name.trim() === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  } else if (role_name.trim().length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  } else {
    req.role_name = role_name.trim();
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
