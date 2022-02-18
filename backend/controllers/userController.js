const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/userModel')

// @desc Register new user
// @route POST /api/users
// @access Public
exports.registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body

  // form validation
  if (!name || !email || !password) {
    res.status(400)
    throw new Error('Please add all fields')
  }
  // check if user exists
  const userExists = await User.findOne({ email })

  if ( userExists ) {
    res.status(400)
    throw new Error("User already exists")
  }

  // Hash password
  const salt = await bcrypt.genSalt(10)
  const hashedPassword = await bcrypt.hash(password, salt)

  // Create user 
  const user = await User.create({
    name,
    email,
    password: hashedPassword
  })

  if (!user) {
    res.status(400)
    throw new Error('Invalid User Data')
  }

  res.status(201).json({
    _id: user.id,
    name: user.name,
    email: user.email,
    token: this.generateToken( user._id )
  })
  
})

// @desc Authenticate a user
// @route POST /api/users/login
// @access Public
exports.loginUser = asyncHandler(async (req, res) => {
  const { email, password } = req.body

  // check for user email
  const user = await User.findOne({ email })
  const verifyPassword = await bcrypt.compare(password, user.password)

  if ( user && await bcrypt.compare(password, user.password) ) {
    res.json({
      _id: user.id,
      name: user.name,
      email: user.email,
      token: this.generateToken( user._id )
    })
  } else {
    res.status(400)
    throw new Error('Invalid credentials')
  }


  

  // console.log(user)
})

// @desc Get user data
// @route GET /api/users/me
// @access Private
// to protect a route, we use middleware (a custom piece of middleware)
exports.getMe = asyncHandler(async (req, res) => {
  const { _id, name, email } = await User.findById(req.user.id)


  res.status(200).json({ 
    id: _id,
    name,
    email
  })
})

// generate JWT
exports.generateToken = (id) => {
  // .sign( data, secret, option )
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '30d'
  })
}