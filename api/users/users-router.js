const router = require("express").Router();

const Users = require("./users-model.js");
const restricted = require("../auth/restricted-middleware.js");
const checkRole = require("../auth/check-role-middleware.js");

router.get("/", restricted, checkRole("admin"), (req, res) => {
  Users.find()
    .then((users) => {
      res.json(users);
    })
    .catch((err) => res.send(err));
});

router.get("/limited", restricted, checkRole("user"), (req, res) => {
  Users.findBy({ username: req?.decodedJWT?.username })
    .then(([user]) => {
      res.json(user);
    })
    .catch((err) => res.send(err));
});

module.exports = router;
