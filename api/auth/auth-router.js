const bcryptjs = require("bcryptjs");

const router = require("express").Router();
const jwt = require("jsonwebtoken");
const secrets = require("../config/secrets");
const server = require("../server");

const Users = require("../users/users-model.js");
const { isValid } = require("../users/users-service.js");

router.post("/register", (req, res) => {
  const credentials = req.body;

  if (isValid(credentials)) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;

    // hash the password
    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;

    // save the user to the database
    Users.add(credentials)
      .then((user) => {
        res.status(201).json({ data: user });
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password and the password should be alphanumeric",
    });
  }
});

router.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (isValid(req.body)) {
    Users.findBy({ username: username })
      .then(([user]) => {
        // compare the password the hash stored in the database
        if (user && bcryptjs.compareSync(password, user.password)) {
          //
          //
          //after we have a user anc cheked their credentials, we're
          //going to create a token by passing using the generateToken
          //func and passing the user into it

          const token = generateToken(user);
          //
          //on the response bellow we are sending the token
          res.status(200).json({ message: `Welcome ${user.username}`, token });
        } else {
          res.status(401).json({ message: "Invalid credentials" });
        }
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password and the password shoud be alphanumeric",
    });
  }
});

function generateToken(user) {
  //the three things we need to create a token:
  const payload = {
    subject: user.id,
    username: user.username,
    role: user.role,
  };

  const secret = secrets.jwtSecret;

  const options = {
    expiresIn: "1h",
  };

  //after all three parts have been created, return...
  return jwt.sign(payload, secret, options);
}

module.exports = router;
