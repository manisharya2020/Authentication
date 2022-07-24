//jshint esversion:6
// Including all file
require('dotenv').config()
const express = require('express');
const bodyParser = require("body-parser");
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const flash = require("connect-flash");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret: "ourLittleSecret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
// ********************
// userDB
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  githubId:String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID_GOOGLE,
    clientSecret: process.env.CLIENT_SECRET_GOOGLE,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      username: profile.displayName,
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.CLIENT_ID_GITHUB,
    clientSecret:process.env.CLIENT_SECRET_GITHUB ,
    callbackURL: "http://localhost:3000/auth/github/secrets",
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({
      username: profile.username,
      githubId: profile.id
    }, function(err, user) {
      return done(err, user);
    });
  }
));
// ***********

// Home route
app.route("/")
  .get(function(req, res) {
    if (req.isAuthenticated()) {
      res.redirect("/secrets")
    } else {
      res.render("home");
    }
  });
// *************

// Secret route
app.route("/secrets")
  .get(function(req, res) {
    User.find({
      "secret": {
        $ne: null
      }
    }, function(err, result) {
      res.render("secrets", {
        userWithSecrets: result
      });
    });

  });

// **************

// google Oauth route
app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  }));

app.get("/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  function(req, res) {
    res.redirect("/");
  });
// *******************
// Github auth
app.get("/auth/github",
  passport.authenticate("github", {
    scope: ["profile"]
  }));

  app.get("/auth/github/secrets",
    passport.authenticate("github", {
      failureRedirect: "/login"
    }),
    function(req, res) {
      res.redirect("/");
    });
// ***************

// Login route
app.route("/login")
  .get(function(req, res) {
    const message = req.flash("error");
    res.render("login", {
      message
    });
  })
  .post(function(req, res) {
    User.findOne({
      username: req.body.username
    }, function(err, result) {
      if (err) {
        console.log(err);
      } else {
        if (result) {
          const user = new User({
            username: req.body.username,
            password: req.body.password
          });
          req.login(user, function(err) {
            if (err) {
              console.log(err);
              res.redirect("/login");
            } else {
              passport.authenticate("local")(req, res, function() {
                res.redirect("/");
              });
            }
          });
        } else {
          req.flash("error", "Username and/or Password is invalid");
          res.redirect("/login");

        }
      }
    });
  });
// ***********

// logout route
app.route("/logout")
  .get(function(req, res) {
    req.logout(function(err) {
      if (err) {
        console.log(err);
      }
      res.redirect("/");
    });
  });
// *******************

// Register route
app.route("/register")
  .get(function(req, res) {
    const message = req.flash("error");
    res.render("register", {
      message
    });
  })
  .post(function(req, res) {
    User.register({
      username: req.body.username
    }, req.body.password, function(err, user) {
      if (err) {
        req.flash("error", "Username exists");
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/");
        });
      }
    });
  });

// **************

// submit route
app.route("/submit")
  .get(function(req, res) {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.render("home");
    }
  })
  .post(function(req, res) {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, function(err, result) {
      if (err) {
        console.log(err);
      } else {
        if (result) {
          result.secret = submittedSecret;
          result.save();
          res.redirect("/secrets");
        }
      }

    });
  });
// *****************

// Port
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
// *******************
