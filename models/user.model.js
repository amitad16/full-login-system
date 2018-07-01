const mongoose = require('mongoose');
const { Schema }= mongoose;
const bcrypt = require('bcryptjs');

const UserSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  username: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  profileImg: {
    type: Schema.Types.Mixed,
    required: false
  },
  resetToken: {
    type: String,
    required: false
  }
});

UserSchema.pre('save', function (next) {
  let user = this;

  if (user.isModified('password')) {
    user.password = hashPassword(user);
    next();
  } else {
    next();
  }
});

UserSchema.statics.findByCredentials = function (username, callback) {
  let User = this;

  const query = { username: username };
  User.findOne(query, callback);
};

UserSchema.statics.getUserById = function (id, callback) {
  let User = this;
  User.findById(id, callback);
};

// Helper functions ***************************************************************
// Hash password
let hashPassword = (user) => {
  let salt = bcrypt.genSaltSync(10);
  return bcrypt.hashSync(user.password, salt);
};

// Compare the password during login
UserSchema.statics.comparePassword = (userPassword, hash, callback) => {
  bcrypt.compare(userPassword, hash, (err, isMatch) => {
    if(err) throw err;
    callback(null, isMatch);
  });
};

const User = mongoose.model('User', UserSchema);

module.exports = { User };
