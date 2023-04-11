"use strict";

const { SECRET_KEY } = require("../config");
const { BadRequestError } = require("../expressError");

const Router = require("express").Router;
const router = new Router();
const jwt = require("jsonwebtoken");
const User = require("../models/user");
/** POST /login: {username, password} => {token} */
router.post("/login", async function (req, res, next) {
  if (!("username" in req.body) || !("password" in req.body))
    throw new BadRequestError("Username and password required!");

  const { username, password } = req.body;

  const authorizedLogin = await User.authenticate(username, password);
  if (!authorizedLogin) throw new BadRequestError("Invalid username/password!");

  await User.updateLoginTimestamp(username);

  let payload = { username };
  const token = jwt.sign(payload, SECRET_KEY);

  return res.json({ token });
});

/** POST /register: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 */

router.post("/register", async function (req, res, nest) {
  const registerFields = [
    "username",
    "password",
    "first_name",
    "last_name",
    "phone",
  ];
  const validRequest = registerFields.every((field) => req.body[field]);
  if (!validRequest) throw new BadRequestError("Invalid request body!");

  //TODO: just pass in req.body?
  const { username, password, first_name, last_name, phone } = req.body;
  const user = await User.register(
    username,
    password,
    first_name,
    last_name,
    phone
  );

  let payload = { username: user.username };
  const token = jwt.sign(payload, SECRET_KEY);

  return res.json({ token });
});

module.exports = router;
