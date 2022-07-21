//jshint esversion:6
// Including all file
require('dotenv').config()
const express = require('express');
const bodyParser = require("body-parser");
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

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
// encryption
const secret = process.env.SECRET;
userSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});
// ************
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
        if (user.password === password) {
          res.render("secrets");
        } else {
            res.send('Did not find any account with this username.');
        }
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
    const newUser = new User({
      email: req.body.username,
      password: req.body.password
    });
    newUser.save(function(err) {
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    })
  });
// **************

// Port
app.listen(3000, function() {
  console.log("Server started on port 3000");
});
// *******************
// ***********
