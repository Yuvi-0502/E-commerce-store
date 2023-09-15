const User = require("../models/user");
const { check, validationResult } = require("express-validator");
var expressjwt = require("express-jwt");
var jwt = require("jsonwebtoken");
//var token = jwt.sign({ foo: 'bar' }, 'shhhhh');

exports.signup = (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({
        error: errors.array()[0].msg,   
      });
    }
  
    const body = req.body;
  
    User.findOne({ email: body.email }, (err, existingUser) => {
      if (err) {
        return res.status(500).json({
          error: "Internal server error",
        });
      }
  
      if (existingUser) {
        return res.status(400).json({
          error: "User already exists with this email",
        });
      }
  
      // If no errors and user doesn't exist, create a new user
      const user = new User(body);
  
      user.save((err, newUser) => {
        if (err) {
          return res.status(500).json({
            error: "Unable to save user information in the database",
          });
        }
  
        // User creation was successful, send a success response
        res.json({
          name: newUser.name,
          email: newUser.email,
          id: newUser._id,
        });
      });
    });
  };
  
  // console.log("REQ BODY",req.body);
  // res.json({
  //     messsage:"signup route works!"
  // })


exports.signin = (req, res) => {
  const { email, password } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      error: errors.array()[0].msg,
    });
  }
  User.findOne({ email }, (err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User email does not exist",
      });
    }
    // console.log("hello");
    if (!user.authenticate(password)) {
      return res.status(401).json({
        error: "Email and password do not match",
      });
    }
    //create token
    const token = jwt.sign({ _id: user._id }, process.env.SECRET);
    //put token in cookie
    res.cookie("token", token, { expire: new Date() + 9999 });
    //send response to frontend
    const { _id, name, email, role } = user;
    return res.json({ token, user: { _id, name, email, role } });
  });
};

exports.signout = (req, res) => {
  res.clearCookie("token");
  res.json({
    messsage: "User signout",
  });
};

//protected routes
exports.isSignedIn = expressjwt({
  secret: process.env.SECRET,
  userProperty: "auth",
  algorithms: ["sha1", "RS256", "HS256"],
});

//custom middlewares
exports.isAuthenticate = (req, res, next) => {
  let checker = req.profile && req.auth && req.profile._id == req.auth._id;
  if (!checker) {
    return res.status(403).json({
      error: "ACCESS DENIED",
    });
  }
  next();
};

exports.isAdmin = (req, res, next) => {
  if (req.profile.role === 0) {
    return res.status(403).json({
      error: "You are not Admin,Access Denied",
    });
  }
  next();
};
