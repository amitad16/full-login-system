const express = require('express');
const router = express.Router();
const {check, validationResult} = require("express-validator/check");
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const nodemailer = require('nodemailer');
const multer = require('multer');
const jwt = require('jsonwebtoken');

const path = require('path');
const url = require('url');

const mongoose = require('../server/db/mongoose');
const { User } = require('../models/user.model');

// Multer Configurations
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/images/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
  }
});

// Init Upload
const upload = multer({
  storage: storage,
  limits:{fileSize: 1000000},
  fileFilter: function(req, file, cb){
    checkFileType(file, cb);
  }
}).single('profileImg');

// Check File Type
let checkFileType = (file, callback) =>{
  // Allowed ext
  const filetypes = /jpeg|jpg|png|gif/;
  // Check ext
  const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
  // Check mime
  const mimetype = filetypes.test(file.mimetype);

  if(mimetype && extname){
    return callback(null,true);
  } else {
    console.log('Images only');
    callback(new Error('Error: Images Only!'));
  }
};

const EMAIL_REGEX = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

// Access Control
let ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error', 'You are not authorized to view that page.');
    res.redirect('/login');
  }
};

let restrictNonSessionRoutes = (req, res, next) => {
  if (req.isAuthenticated()) {
    req.flash('error', 'You are not authorized to view that page.');
    res.redirect('/');
  } else {
    return next();
  }
};

// ROUTES////////////////////////////
router.get('/', ensureAuthenticated, (req, res, next) => {
  User.findOne({ username: req.user.username })
    .select({name: 1, username: 1, email: 1, 'profileImg.filename': 1})
    .exec()
    .then(user => {
      console.log(user);
      res.status(200).render('index', { user });
    })
    .catch(err => {
      res.status(500).json({
        error: err
      });
    });
});

// Register Form
router.get('/register', restrictNonSessionRoutes, (req, res, next) => {
  res.render('register', { title: 'Register' });
});

// Login Form
router.get('/login', restrictNonSessionRoutes, (req, res, next) => {
  res.render('login', { title: 'Login' });
});

router.get('/logout', (req, res, next) => {
  req.logout();
  req.flash('success', 'You are logged out');
  res.redirect('/login');
});

router.get('/forgotPassword', restrictNonSessionRoutes, (req, res, next) => {
  res.render('forgot-password');
});

router.get('/resetPassword/:resetToken', restrictNonSessionRoutes, (req, res, next) => {
  const resetToken = req.params.resetToken;
  res.render('resetPassword', { resetToken });
});

router.post('/resetPassword/:resetToken', restrictNonSessionRoutes, [
  check('password', 'Password must be between 6 and 18 characters')
    .isLength({ min: 6, max: 18 }),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
], (req, res, next) => {
  const resetToken = req.params.resetToken;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log('Errors: ', errors.mapped());
    // res.render('resetPassword', { errors: errors.mapped() });
  } else {
    const newPassword = req.body.password;

    jwt.verify(resetToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.log('TOKEN ERROR: ', err);
        User.findOneAndUpdate({'resetToken': resetToken}, {'$unset': {'resetToken': 1}})
          .then(() => {
            req.flash('error', 'Token Expired, write email again');
            res.render('forgot-password');
          });
      } else {
        User.findOneAndUpdate({ 'resetToken': resetToken }, { '$unset': { 'resetToken': 1 } }, { 'new': true })
          .then(user => {
            if (!user) {
              console.log('No user');
              req.flash('error', 'Please send new mail <a href="http://localhost:3000/forgotPassword">http://localhost:3000/forgotPassword</a>');
              res.redirect('/forgotPassword');
            }
            user.password = newPassword;
            user.save()
              .then(() => {
                console.log('user: ', user);
                req.flash('success', 'Password changed successfully can login');
                res.redirect('/login');
              })
              .catch(err => res.status(400).send(err));
          });
      }
    });
  }
});

// Process Register
router.post('/register', upload, [
  check('name', 'Name must be 3 characters long')
    .trim()
    .isLength({ min: 3 }),
  check('username', 'Username must be 3 characters long')
    .trim()
    .isLength({ min: 3 }),
  check('email', 'Invalid Email')
    .trim()
    .custom((value) => EMAIL_REGEX.test(value) === true),
  check('password', 'Password must be between 6 and 18 characters')
    .isLength({ min: 6, max: 18 }),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
], (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log('Errors: ', errors.mapped());
    res.render('register', { errors: errors.mapped() });
  } else {
    const userInfo = req.body;
    delete userInfo.password2;
    userInfo.profileImg = req.file;
    const user = new User(userInfo);

    console.log(user);
    user.save()
      .then(() => {
        console.log('user: ', user);
        req.flash('success', 'You are registered and can login');
        res.redirect('/login');
      })
      .catch(err => res.status(400).send(err));}
});

passport.use(new LocalStrategy(
  (username, password, done) => {
    User.findByCredentials(username, (err, user) => {
      if (err) throw err;
      if (!user) {
        return done(null, false, {message: 'Invalid Username or Password'});
      }
      User.comparePassword(password, user.password, (err, isMatch) => {
        if(err) throw err;
        if(isMatch){
          return done(null, user);
        } else {
          return done(null, false, {message: 'Invalid Username or Password'});
        }
      });
    });
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.getUserById(id, (err, user) => {
    done(err, user);
  });
});

router.post('/login', (req, res, next) => {
  console.log("/login: ", req.body);
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  })(req, res, next);
});

// Send Email
router.post('/forgotPassword', restrictNonSessionRoutes, (req, res) => {
  const resetToken = jwt.sign({email: req.body.email.toString(), access: 'resetpassword'}, process.env.JWT_SECRET, { expiresIn: '1d' }).toString();
  User.findOneAndUpdate({ 'email': req.body.email }, { '$set': { 'resetToken': resetToken } }, { 'new': true, 'projection': { 'resetToken': 1 } })
    .then((user) => {
      let transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
          user: process.env.EMAIL_ID,
          pass: process.env.EMAIL_PASSWORD
        }
      });

      let message = {
        from: 'passportlogin@gmail.com',
        to: req.body.email,
        subject: 'Password Change Request',
        text: `Paste this link in your browser http://localhost:3000/resetPassword/${user.resetToken}`,
        html: `<p>Sender Info</p>` +
        `<ul>` +
        `<li>Sender Email: ${req.body.email}</li>` +
        `<li>Click on link: <a href="http://localhost:3000/resetPassword/${user.resetToken}">http://localhost:3000/resetPassword/${user.resetToken}</a></li>` +
        `</ul>`
      };

      transporter.sendMail(message, (err, info) => {
        if (err)
          return console.log(err);
        console.log(info);
        req.flash('success', 'Email Sent to your email id');
        res.render('forgot-password');
      });

    });
});

module.exports = router;
