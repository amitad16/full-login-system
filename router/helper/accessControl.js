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

module.exports = {
  ensureAuthenticated,
  restrictNonSessionRoutes
};