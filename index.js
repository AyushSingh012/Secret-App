import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10; // Number of rounds for bcrypt password hashing
env.config(); // Load environment variables from .env file

// Configure session middleware for user authentication
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Secret key to sign the session ID
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Initialize Passport for authentication
app.use(passport.initialize());
app.use(passport.session());

// Set up PostgreSQL database connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Route to render the home page
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// Route to render the login page
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// Route to render the registration page
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Route to handle user logout
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Route to display user secrets (protected route)
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      // Fetch the user's secret from the database
      const result = await db.query(
        `SELECT secret FROM users WHERE email = $1`,
        [req.user.email]
      );
      const secret = result.rows[0].secret;
      res.render("secrets.ejs", { secret: secret || "You should submit a secret" });
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

// Route to render the secret submission page (protected route)
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

// Route to initiate Google OAuth2 authentication
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"], // Request user profile and email from Google
  })
);

// Route to handle Google OAuth2 callback
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Route to handle local login
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Route to handle user registration
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    // Check if the user already exists
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      // Hash the password and insert the new user into the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          // Log the user in after registration
          req.login(user, (err) => {
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

// Route to handle secret submission
app.post("/submit", async function (req, res) {
  const submittedSecret = req.body.secret;
  try {
    // Update the user's secret in the database
    await db.query(`UPDATE users SET secret = $1 WHERE email = $2`, [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.log(err);
  }
});

// Configure local authentication strategy
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1 ", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        // Compare the provided password with the stored hashed password
        bcrypt.compare(password, user.password, (err, valid) => {
          if (err) return cb(err);
          if (valid) return cb(null, user); // Authentication successful
          else return cb(null, false); // Incorrect password
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

// Configure Google OAuth2 authentication strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // Check if the user exists in the database
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          // Create a new user if they don't exist
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize and deserialize user for session management
passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});