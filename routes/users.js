"use strict";

const { ensureLoggedIn } = require("../middleware/auth");

const Router = require("express").Router;
const router = new Router();
const User = require('../models/user')

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name}, ...]}
 *
 **/
router.get('/', ensureLoggedIn, async function (req, res, next){

  const users = await User.all()

  return res.json({users});
})


/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/
router.get('/:username', async function (req, res, next){

})

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/
router.get('/:username/to', async function (req, res, next){

})

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get('/:username/from', async function (req, res, next){

})
module.exports = router;