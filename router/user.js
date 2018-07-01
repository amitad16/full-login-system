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



module.exports = router;
