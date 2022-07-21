//jshint esversion:6
// Including all file
require('dotenv').config()
const express = require('express');
const bodyParser = require("body-parser");
const ejs = require('ejs');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const saltrounds = 10;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true
});
// ********************
// userDB
const userSchema = new mongoose.Schema({
  email: String,
  password: String
});
const User = mongoose.model("User", userSchema);
// ***********
// Home route
app.route("/")
  .get(function(req, res) {
    res.render("home");
  });
// *************

// Login route
app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })
  .post(function(req, res) {
    const username = req.body.username;
    const password = req.body.password;
    User.findOne({
      email: username
    }, function(err, user) {
      if (err) {
        console.log(err);
      } else {
        bcrypt.compare(req.body.password, user.password, function(err, result) {
          if (result == true) {
            res.render("secrets");
          } else {
            res.send('Did not find any account with this username.');
          }
        });
      }
    })
  });
// ***********

// Register route
app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res) {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
      if(err){
        console.log(err);
      }
      const newUser = new User({
        email: req.body.username,
        password: hash
      });
      newUser.save(function(err) {
        if (err) {
          console.log(err);
        } else {
          res.render("secrets");
        }
      })
    });
  });

// **************

// Port
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
// *******************
