const express = require('express');
const router = express.Router();
const {check, validationResult} = require("express-validator/check");
const passport = require('passport');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');

const path = require('path');

const mongoose = require('../server/db/mongoose');
const { User } = require('../models/user.model');
const { upload } = require('./helper/multerConfigurations');
const { ifLoggedIn, ifNotLoggedIn } = require('./helper/accessControl');
const passportConfig = require('./helper/passport');

const EMAIL_REGEX = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;

// Register Form
router.get('/register', ifNotLoggedIn, (req, res, next) => {
  res.render('register', { title: 'Register' });
});

// Login Form
router.get('/login', ifNotLoggedIn, (req, res, next) => {
  res.render('login', { title: 'Login' });
});

router.get('/logout', ifLoggedIn, (req, res, next) => {
  req.logout();
  req.flash('success', 'You are successfully logged out');
  res.redirect('/user/login');
});

router.get('/forgotPassword', ifNotLoggedIn, (req, res, next) => {
  res.render('forgotPassword');
});

router.get('/resetPassword/:resetToken', ifNotLoggedIn, (req, res, next) => {
  const resetToken = req.params.resetToken;
  res.render('resetPassword', { resetToken });
});

// Process Register
router.post('/register', ifNotLoggedIn, upload, [
  check('name')
    .trim()
    .not().isEmpty().withMessage('Name is required')
    .isLength({ min: 3 }).withMessage('Name must be 3 characters long'),
  check('username')
    .trim()
    .not().isEmpty().withMessage('Username is required')
    .isLength({ min: 3 }).withMessage('Username must be 3 characters long')
    .custom((value) => {
      return new Promise((resolve, reject) => {
        User.findOne({ 'username': value }, { 'username': 1, '_id': 0 }, function(err, user){
          if(err) {
            reject(new Error('Server Error'))
          }
          if(Boolean(user)) {
            reject(new Error('Username already in use'))
          }
          resolve(true)
        });
      });
    }),
  check('email', 'Invalid Email')
    .not().isEmpty().withMessage('Email is required')
    .custom((value) => EMAIL_REGEX.test(value) === true).withMessage('Invalid Email')
    .custom((value) => {
      return new Promise((resolve, reject) => {
        User.findOne({ 'email': value }, { 'email': 1, '_id': 0 })
          .then(user => {
            if (user)
              reject(new Error('Email already in use'));
            resolve(true);
          });
      })
    }),
  check('password', 'Password must be between 6 and 18 characters')
    .not().isEmpty().withMessage('Password is required')
    .isLength({ min: 6, max: 18 }),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
], (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.render('register', { errors: errors.mapped() });
  } else {
    const userInfo = req.body;
    delete userInfo.password2;
    userInfo.profileImg = req.file;
    const user = new User(userInfo);

    user.save()
      .then(() => {
        req.flash('success', 'You are registered and can login');
        res.redirect('/user/login');
      })
      .catch(err => res.status(400).send(err));
  }
});

// Passport Configurations
passportConfig.passportConfig();

router.post('/login', ifNotLoggedIn, (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: `/users/${req.body.username}`,
    failureRedirect: '/user/login',
    failureFlash: true
  })(req, res, next);
});

// Forgot Password
router.post('/forgotPassword', ifNotLoggedIn, [
  check('email')
    .not().isEmpty().withMessage('Email is required')
    .custom((value) => EMAIL_REGEX.test(value) === true).withMessage('Invalid Email')
    .custom((value) => {
      return new Promise((resolve, reject) => {
        User.findOne({ 'email': value }, { 'email': 1, '_id': 0 })
          .then(user => {
            if (!user)
              reject(new Error('Email is not registered with us'));
            resolve(true);
          });
      })
    })
], (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    res.render('forgotPassword', { errors: errors.mapped() });
  } else {
    const resetToken = jwt.sign({email: req.body.email.toString(), access: 'resetpassword'}, process.env.JWT_SECRET, { expiresIn: '24h' }).toString();
    User.findOneAndUpdate(
      { 'email': req.body.email },
      { '$set': { 'resetToken': resetToken } },
      { 'new': true, 'projection': { 'resetToken': 1 } })
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
          text: `Paste this link in your browser http://localhost:3000/user/resetPassword/${user.resetToken}`,
          html: `<p>Sender Info</p>` +
          `<ul>` +
          `<li>Sender Email: ${req.body.email}</li>` +
          `<li>Click on link: <a href="http://localhost:3000/user/resetPassword/${user.resetToken}">http://localhost:3000/user/resetPassword/${user.resetToken}</a></li>` +
          `</ul>`
        };

        transporter.sendMail(message, (err, info) => {
          if (err) {
            req.flash('error', 'Email sent error');
            res.render('forgotPassword');
          }
          req.flash('success', 'Email Sent to your email id');
          res.render('forgotPassword');
        });

      });
  }
});

router.post('/resetPassword/:resetToken', ifNotLoggedIn, [
  check('password', 'Password must be between 6 and 18 characters')
    .not().isEmpty().withMessage('Password is required')
    .isLength({ min: 6, max: 18 }),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
], (req, res, next) => {
  const errors = validationResult(req);
  const resetToken = req.params.resetToken;

  if (!errors.isEmpty()) {
    console.log('Errors: ', errors.mapped());
    // res.render('resetPassword', { errors: errors.mapped() });
    if (errors.mapped().password)
      req.flash('error', errors.mapped().password.msg);
    if (errors.mapped().password2)
      req.flash('error', errors.mapped().password2.msg);
    res.redirect(`/user/resetPassword/${resetToken}`);
  } else {
    const newPassword = req.body.password;

    jwt.verify(resetToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        User.findOneAndUpdate({'resetToken': resetToken}, {'$unset': {'resetToken': 1}})
          .then(() => {
            req.flash('error', 'Token Expired, write email again');
            res.redirect('/user/forgotPassword');
          });
      } else {
        User.findOneAndUpdate({ 'resetToken': resetToken }, { '$unset': { 'resetToken': 1 } }, { 'new': true })
          .then(user => {
            if (!user) {
              req.flash('error', 'Please send new mail <a href="http://localhost:3000/forgotPassword">http://localhost:3000/forgotPassword</a>');
              res.redirect('/user/forgotPassword');
            }
            user.password = newPassword;
            user.save()
              .then(() => {
                req.flash('success', 'Password changed successfully can login');
                res.redirect('/user/login');
              })
              .catch(err => res.status(400).send(err));
          });
      }
    });
  }
});

module.exports = router;
