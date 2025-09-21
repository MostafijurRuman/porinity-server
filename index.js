// ==================== CORE IMPORTS ====================
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const port = process.env.PORT || 5000;

// ==================== MIDDLEWARES ====================
app.use(
  cors({
    origin: [
      "http://localhost:5173", // frontend local
      "https://your-client-app.web.app", // replace with your deployed frontend
    ],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// ==================== DATABASE ====================
// Vercel-friendly connection (connect once, reuse)


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fk4sfju.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;





const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// Global collections
let BiodataCollection;
let UsersCollection;

let isDBInitialized = false;

async function initDB() {
  if (!isDBInitialized) {
    await client.connect();
    const db = client.db("PorinityDB");
    
    // Initialize all collections
    BiodataCollection = db.collection("BiodataCollection");
    UsersCollection = db.collection("Users");
    
    isDBInitialized = true;
    console.log("✅ MongoDB connected and collections initialized");
  }
}

// Middleware → ensure DB is initialized
app.use(async (req, res, next) => {
  try {
    await initDB();
    next();
  } catch (err) {
    console.error("DB connection error:", err);
    res.status(500).json({ message: "Database connection failed" });
  }
});

// ==================== AUTH (JWT) ====================

// Issue tokens (Access + Refresh)
app.post("/jwt", (req, res) => {
  const user = req.body; // { email, uid, role, ... }
  const isProd = process.env.NODE_ENV === "production";

  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "strict",
    })
    .send({ success: true });
});

// Refresh token
app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  const isProd = process.env.NODE_ENV === "production";

  if (!refreshToken) {
    return res.status(401).send({ message: "No refresh token" });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Invalid refresh token" });

    const newAccessToken = jwt.sign(
      { email: decoded.email, uid: decoded.uid },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res
      .cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: isProd,
        sameSite: "strict",
      })
      .send({ success: true });
  });
});

// Logout → clear tokens
app.post("/logout", (req, res) => {
  const isProd = process.env.NODE_ENV === "production";
  res
    .clearCookie("accessToken", {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
      path: "/",
    })
    .clearCookie("refreshToken", {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
      path: "/",
    })
    .send({ success: true });
});

// Verify Access Token middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.accessToken;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized Access" });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res
        .status(403)
        .send({ message: "Access Token Expired or Invalid" });
    }
    req.user = decoded; // decoded {email, uid, role,...}
    next();
  });
};

// ==================== EXAMPLE CRUD APIS ====================

// Public route
app.get("/", (req, res) => {
  res.send("🚀Porinity server is running...");
});



// ==================== LOCAL VS VERCEL ====================
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () =>
    console.log(`🚀 Porinity Server running  on port ${port}`)
  );
}

module.exports = app;

