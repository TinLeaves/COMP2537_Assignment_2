require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3020;

const app = express();

const Joi = require("joi");

app.use('/public', express.static('public'));

app.set('view engine', 'ejs');

const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// var { database } = include('databaseConnection');
const { database } = require('./databaseConnection');


const userCollection = database.db(mongodb_database).collection('users');

// const { ObjectId } = require('mongodb');
const { MongoClient, ObjectId } = require('mongodb');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true
}
));

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  }
  else {
    res.redirect('/login');
  }
}

function isAdmin(req) {
  if (req.session.user_type == 'admin') {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("403", { error: "Not Authorized" });
    return;
  }
  else {
    next();
  }
}

app.get('/', (req, res) => {
  const authenticated = req.session.authenticated;
  const username = req.session.username;

  res.render('index', { authenticated, username });
});

// app.get('/members', (req, res) => {
//   if (!req.session.authenticated) {
//     res.redirect('/login');
//     return;
//   }

//   const images = ['atSad.gif', 'atVibe.gif', 'atSoupMe.gif'];
//   const randomIndex = Math.floor(Math.random() * images.length);
//   const randomImage = '/public/' + images[randomIndex];

//   res.send(`
//       <h1>Hello, ${req.session.username}.</h1>
//       <img src="${randomImage}">
//       <form action="/logout" method="GET">
//         <button type="submit">Sign out</button>
//       </form>
//     `);
// });

app.get('/members', (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  const images = ['atSad.gif', 'atVibe.gif', 'atSoupMe.gif'];
  const randomIndex = Math.floor(Math.random() * images.length);
  const randomImage = '/public/' + images[randomIndex];

  res.render('members', { username: req.session.username, randomImage });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/signup', (req, res) => {
  res.render('signup');
});

app.post('/signupSubmit', async (req, res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

// Check for empty fields
let errorMsg = "";
if (!username) {
  errorMsg += "Name is required.";
}
if (!email) {
  errorMsg += "Email is required.";
}
if (!password) {
  errorMsg += "Password is required.";
}
if (errorMsg !== "") {
  res.render('signupSubmit', { errorMsg: errorMsg });
  return;
}

  // Validate inputs using Joi
  const schema = Joi.object(
    {
      username: Joi.string().alphanum().max(20).required(),
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required()
    });

  const validationResult = schema.validate({ username, email, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/signup");
    return;
  }

  // Check if username already exists
  const existingUser = await userCollection.findOne({ username: { $eq: username } });
  if (existingUser) {
    const errorMsg = "Username already exists.";
    res.render('signupSubmit', { errorMsg: errorMsg });
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  // Add user to MongoDB database using parameterized query
  await userCollection.insertOne({
    username,
    email,
    password: hashedPassword,
    user_type: "user", // Assigning a default user_type of "user"
  });

  console.log("Inserted user");

  // Set session variables
  req.session.authenticated = true;
  req.session.username = username;
  req.session.email = email;
  req.session.user_type = "user";

  res.redirect("/members");
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/loginSubmit', async (req, res) => {
  // extract email and password from request body
  const { email, password } = req.body;

  // validate email using Joi
  const emailSchema = Joi.string().email().required();
  const emailValidationResult = emailSchema.validate(email);
  if (emailValidationResult.error != null) {
    console.log(emailValidationResult.error);
    res.redirect('/login');
    return;
  }

  // find user in database using email
  const user = await userCollection.findOne({ email });
  if (!user) {
    console.log('invalid email/password combination');
    const errorMsg = 'Invalid email/password combination.';
    res.render('loginSubmit', { errorMsg: errorMsg });
    return;
  }

  // compare password with stored BCrypted password
  const isPasswordMatch = await bcrypt.compare(password, user.password);
  if (!isPasswordMatch) {
    console.log('password is incorrect');
    const errorMsg = 'Password is incorrect.';
    res.render('loginSubmit', { errorMsg: errorMsg });
    return;
  }

  // store username in session
  req.session.authenticated = true;
  req.session.username = user.username;
  req.session.cookie.maxAge = expireTime;
  req.session.user_type = user.user_type;

  // redirect to members page
  res.redirect('/members');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
  if (!req.session.authenticated) {
    res.redirect('/login');
    return;
  }

  if (!isAdmin(req)) {
    res.status(403);
    res.render("403", { error: "Not Authorized" });
    return;
  }

  const result = await userCollection.find({}, { projection: { username: 1, user_type: 1 } }).toArray();

  res.render("admin", { users: result });
});

app.get('/admin/demote', async (req, res) => {
  var user = req.query.user;

  // Update user'a user_type using parameterized query
  await userCollection.updateOne({ username: { $eq: user } }, { $set: { user_type: "user" } });

  res.redirect("/admin");
});

app.get('/admin/promote', async (req, res) => {
  var user = req.query.user;

  // Update user's user_type using parameterized query
  await userCollection.updateOne({ username: { $eq: user } }, { $set: { user_type: "admin" } });

  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
