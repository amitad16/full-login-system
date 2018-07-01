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

module.exports = {
  ifLoggedIn,
  ifNotLoggedIn
};