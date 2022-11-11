const app = require("express")();
require("dotenv").config();
const GoogleStrategy = require("passport-google-oauth2").Strategy;

//passport is used for authenticating the request
const passport = require("passport");
const session = require("express-session");
let userDetails = {};
app.use(
  session({
    resave: false,
    saveUninitialized: false,
    secret: process.env.SECRET,
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate("session"));

// To persist user data (after successful authentication) into session.
passport.serializeUser(function (user, callback) {
  callback(null, user);
});

// To retrieve user data from session.
passport.deserializeUser(function (obj, callback) {
  callback(null, obj);
});

// The client ID and secret obtained when creating an application are supplied as options when creating the strategy.
// The strategy also requires a verify callback, which receives the access token and optional refresh token, as well as profile which contains the authenticated user's Google profile.
// The verify callback must call cb providing a user to complete authentication
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
      passReqToCallback: true,
    },
    async (request, accessToken, refreshToken, profile, done) => {
      try {
        userDetails = {
          id: profile.id,
          name: profile.displayName,
          accessToken,
          refreshToken,
        };
        return done(null, true);
      } catch (error) {
        return done(error, false);
      }
    }
  )
);

// Setup for rendering ejs in browser
app.set("view engine", "ejs");

// Login page
app.get("/", function (req, res) {
  res.render("pages/auth");
});

// When user logout
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("https://accounts.google.com/logout");
  });
});

app.get("/success", (req, res) =>
  res.render("pages/success", { user: userDetails })
);

app.get("/error", (req, res) => {
  res.send("error logging in");
});

// Google strategy is used to authenticate and define scope
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: [
      "https://mail.google.com/",
      "https://www.googleapis.com/auth/userinfo.profile",
    ],
    accessType: "offline",
    prompt: "consent",
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/error" }),
  function (req, res) {
    // Successful authentication, redirect success.
    res.redirect("/success");
  }
);

//error handling middleware
app.use((error, req, res, next) => {
  console.log(error);
  const status = error.statusCode || 500;
  const message = error.message;
  res.status(status).json({ message: message });
});

app.listen(process.env.PORT, () =>
  console.log(`App started at ${process.env.PORT}`)
);
