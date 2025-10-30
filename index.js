import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import User from "./models/User.js";
import Comment from "./models/Comment.js";

dotenv.config();
const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(session({ secret: "secret", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Admin Middleware
const authenticateAdmin = (req, res, next) => {
  // This is a simple admin check - in production you'd want a more secure method
  const adminToken = req.headers['authorization'];
  if (adminToken && adminToken === 'Bearer admin-token') {
    next();
  } else {
    res.status(401).json({ message: "Admin access required" });
  }
};

// 🔐 Google OAuth setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          user = await User.create({
            googleId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            photo: profile.photos[0].value,
          });
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

// 🧭 Routes
app.get("/", (req, res) => {
  res.json({ message: "Backend is running!" });
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: process.env.FRONTEND_URL }),
  (req, res) => {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.redirect(`${process.env.FRONTEND_URL}/?token=${token}`);
  }
);

app.get("/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-__v");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// 💬 Comment routes
app.get("/comments", async (req, res) => {
  try {
    const comments = await Comment.find().populate("userId", "name photo email").sort({ timestamp: -1 });
    res.json(comments);
  } catch (error) {
    res.status(500).json({ message: "Error fetching comments" });
  }
});

app.post("/comments", authenticateToken, async (req, res) => {
  try {
    const { text } = req.body;
    const comment = await Comment.create({ 
      userId: req.user.id, 
      text,
      approved: false, // All comments need admin approval
      timestamp: new Date()
    });
    const populated = await comment.populate("userId", "name photo email");
    res.status(201).json(populated);
  } catch (error) {
    res.status(500).json({ message: "Error creating comment" });
  }
});

// 🔐 Admin Routes for comment management
app.patch("/comments/:id/approve", async (req, res) => {
  try {
    const comment = await Comment.findByIdAndUpdate(
      req.params.id,
      { approved: true },
      { new: true }
    ).populate("userId", "name photo email");
    
    if (!comment) {
      return res.status(404).json({ message: "Comment not found" });
    }
    
    res.json(comment);
  } catch (error) {
    res.status(500).json({ message: "Error approving comment" });
  }
});

app.delete("/comments/:id", async (req, res) => {
  try {
    const comment = await Comment.findByIdAndDelete(req.params.id);
    
    if (!comment) {
      return res.status(404).json({ message: "Comment not found" });
    }
    
    res.json({ message: "Comment deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error deleting comment" });
  }
});

// 🧪 Add test comments route (for testing)
app.get("/test-comments", async (req, res) => {
  try {
    // Create a test user first
    let testUser = await User.findOne({ email: "test@example.com" });
    if (!testUser) {
      testUser = await User.create({
        googleId: "test123",
        name: "Test User",
        email: "test@example.com",
        photo: ""
      });
    }

    // Create test comments
    const testComments = [
      { userId: testUser._id, text: "This is a great portfolio!", approved: true },
      { userId: testUser._id, text: "Amazing work! 👏", approved: true },
      { userId: testUser._id, text: "Waiting for approval...", approved: false }
    ];

    await Comment.deleteMany({});
    await Comment.insertMany(testComments);

    const allComments = await Comment.find().populate("userId", "name photo email");
    res.json({ message: "Test comments added!", comments: allComments });
  } catch (error) {
    res.status(500).json({ message: "Error adding test comments", error });
  }
});

// Health check for database
app.get("/health", async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ 
      status: "OK", 
      database: "Connected",
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ 
      status: "Error", 
      database: "Disconnected",
      error: error.message 
    });
  }
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  })
  .catch((err) => console.error("MongoDB connection error:", err));