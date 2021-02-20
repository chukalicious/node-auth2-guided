const jwt = require("jsonwebtoken");
const secret = require("../config/secrets");

module.exports = (req, res, next) => {
  // add code here to verify users are logged in

  //get the token out of the request from the header
  //Authorization: Bearer <token>
  //an option to declare what's on line: 12
  const token = req.headers?.authorization?.split(" ")[1];

  //const token =
  //req.headers.authorization && req.headers.authorization.split(" ")[1];

  if (token) {
    jwt.verify(token, secret.jwtSecret, (err, decodedToken) => {
      if (err) {
        res.status(401).json({ you: "can't touch this" });
      } else {
        req.decodedJWT = decodedToken;
        next();
      }
    });
  } else {
    res.status(401).json({ you: "shall not pass" });
  }
};
