const { check } = require("express-validator/check");

const { User } = require('../../models/user.model');

const EMAIL_REGEX = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const NAME_REGEX = /^([a-zA-Z ]){3,50}$/;
const PASSWORD_REGEX = /^(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[0-9])(?=.*?[\W]).{6,18}$/;

// Access Control
let ifLoggedIn = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error', 'You are not authorized to view that page.');
    res.redirect('/user/login');
  }
};

let ifNotLoggedIn = (req, res, next) => {
  if (!req.isAuthenticated()) {
    return next();
  } else {
    req.flash('error', 'You are not authorized to view that page.');
    if (req.headers.referer.split('/')[3] === 'users') {
      let username = req.headers.referer.split('/')[4];
      res.redirect(`/users/${username}`);
    } else {
      res.json({ error: 'Route Error' });
    }
  }
};

// Validations
let registrationFormValidation = [
  check('name')
    .trim()
    .not().isEmpty().withMessage('F: Name is required')
    .isLength({ min: 3, max: 50 }).withMessage('F: Name must be between 3-50 characters')
    .custom((value) => NAME_REGEX.test(value) === true).withMessage('F: Should be 3-50 char long, no special characters or numbers.'),
  check('username')
    .trim()
    .not().isEmpty().withMessage('F: Username is required')
    .isLength({ min: 3, max: 50 }).withMessage('F: Username must be between 3-50 characters')
    .isAlphanumeric().withMessage('F: Username should contain alphabets and numbers only')
    .custom((value) => {
      return new Promise((resolve, reject) => {
        User.findOne({ 'username': value }, { 'username': 1, '_id': 0 }, function(err, user){
          if (err) {
            reject(new Error('Server Error'));
          }
          if (Boolean(user)) {
            reject(new Error('Username already in use'));
          }
          resolve(true);
        });
      });
    }),
  check('email', 'Invalid Email')
    .trim()
    .not().isEmpty().withMessage('F: Email is required')
    .custom((value) => EMAIL_REGEX.test(value) === true).withMessage('F: Invalid Email')
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
  check('password')
    .not().isEmpty().withMessage('F: Password is required')
    .isLength({ min: 6, max: 18 }).withMessage('F: Password must be between 6-18 characters')
    .custom(value => PASSWORD_REGEX.test(value) === true)
    .withMessage('F: Password should have at least one lower case, one UPPER CASE, one number, one special character'),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
];

let forgotPasswordFormValidation = [
  check('email')
    .trim()
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
      });
    })
];

let resetPasswordFormValidation = [
  check('password')
    .not().isEmpty().withMessage('Password is required')
    .isLength({ min: 6, max: 18 }).withMessage('Password must be between 6-18 characters')
    .custom(value => PASSWORD_REGEX.test(value) === true)
    .withMessage('Password should have at least one lower case, one UPPER CASE, one number, one special character'),
  check('password2', 'Passwords do not match')
    .custom((value, { req }) => value === req.body.password)
];

module.exports = {
  ifLoggedIn,
  ifNotLoggedIn,
  registrationFormValidation,
  forgotPasswordFormValidation,
  resetPasswordFormValidation
};