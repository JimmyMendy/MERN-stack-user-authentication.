const router = require("express").Router();
const User = require("../models/userModel");
const bycrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");


//Register
router.post("/", async (req, res) => {
  try {
    const {email, password, passwordVerify} = req.body;

    // validation
    if (!email || !password || !passwordVerify)
    return res
      .status(400)
      .json({errorMessage: "please enter all required fields."});

    if(password.length < 6)
    return res
      .status(400)
      .json({errorMessage: "please enter a password of at least 6 characters."});

    if(password !== passwordVerify)
    return res
      .status(400)
      .json({errorMessage: "please enter the same password twice."});
    
    const existingUser = await User.findOne({email: email})
    if (existingUser)
    return res
      .status(400)
      .json({errorMessage: "An account with this email already exists."});

    // hash the password
    const salt = await bycrypt.genSalt();
    const passwordHash = await bycrypt.hash(password, salt);

    // Save new user account to the db
    const newUser = new User({
      email, passwordHash
    });

    const savedUser = await newUser.save();

    // Sign the token
    const token = jwt.sign({
      user: savedUser._id
    }, process.env.JWT_SECRET)
    console.log(token);

    // send the token in a HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
    }).send()

  }
  catch (err) {
    console.error(err);
    res.status(500).send();
  }
  
});

// Log in
router.post("/login", async (req,res) => {
  try {
    const {email, password} = req.body;

    // validate
    if (!email || !password)
      return res
        .status(400)
        .json({errorMessage: "please enter all required fields."});

    const existingUser = await User.findOne({email});
    if (!existingUser)
      return res
        .status(401)
        .json({errorMessage: "Wrong email or password."});

      const passwordCorrect = await bycrypt.compare(
        password, 
        existingUser.passwordHash
      );
      if(!passwordCorrect)
        return res
          .status(401)
          .json({errorMessage: "Wrong email or password."});
    
    // Sign the token
    const token = jwt.sign({
      user: existingUser._id
    }, process.env.JWT_SECRET)
    console.log(token);

    // send the token in a HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
    }).send()
  }
  catch (err) {
    console.error(err);
    res.status(500).send();
  }
});

// LogOut
router.get("/logout", (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0)
  }).send();
});

router.get("/loggedIn", (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.json(false);
    }

    jwt.verify(token, process.env.JWT_SECRET);
    res.send(true)
  }
    catch (err) {
      res.json(false);
  }
});

module.exports = router;