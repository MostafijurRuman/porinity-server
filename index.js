/* eslint-disable */
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
const allowedOrigins = [
  "http://localhost:5173",
  "https://porinity.firebaseapp.com",
  "https://porinity.web.app",
  process.env.CLIENT_URL,
  process.env.ADMIN_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      if (/^http:\/\/(localhost|127\.0\.0\.1):\d+$/i.test(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json());

// ==================== DATABASE ====================
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.fk4sfju.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let BiodataCollection;
let UsersCollection;
let ContactRequestsCollection;
let SuccessStoriesCollection;
let ContactMessagesCollection;
let isDBInitialized = false;

async function initDB() {
  if (!isDBInitialized) {
    await client.connect();
    const db = client.db("PorinityDB");

    BiodataCollection = db.collection("BiodataCollection");
    UsersCollection = db.collection("Users");
    ContactRequestsCollection = db.collection("ContactRequests");
    SuccessStoriesCollection = db.collection("SuccessStories");
    ContactMessagesCollection = db.collection("ContactMessages");

    isDBInitialized = true;
    console.log("✅ MongoDB connected and collections initialized");
  }
}

app.use(async (req, res, next) => {
  try {
    await initDB();
    next();
  } catch (err) {
    console.error("DB connection error:", err);
    res.status(500).json({ message: "Database connection failed" });
  }
});

// ==================== HELPERS ====================
const sanitizeBiodata = (doc = {}, options = {}) => {
  const { includePayment = false } = options;
  const { _id, numericBiodataId, premiumPayment, ...rest } = doc || {};

  if (includePayment && premiumPayment) {
    rest.premiumPayment = {
      ...premiumPayment,
      cardLast4: premiumPayment?.cardLast4 || null,
    };
  }

  return rest;
};

const sanitizeContactMessage = (doc = {}) => {
  if (!doc || typeof doc !== "object") return {};
  const { _id, ...rest } = doc;
  return {
    id: _id ? _id.toString() : undefined,
    ...rest,
  };
};

const extractNumericId = (value) => {
  const digits = String(value ?? "").replace(/[^0-9]/g, "");
  return digits ? Number(digits) : 0;
};

const normalizeString = (value) =>
  typeof value === "string" ? value.trim() : "";

const normalizeNullableString = (value) => {
  const trimmed = normalizeString(value);
  return trimmed || "";
};

const toIsoOrNull = (value) => {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
};

const sanitizeSuccessStory = (doc = {}) => {
  if (!doc || typeof doc !== "object") return {};
  const {
    _id,
    coupleNames = "",
    brideName = "",
    groomName = "",
    story = "",
    rating = 5,
    marriageDate = null,
    weddingCity = "",
    heroImageUrl = "",
    maleImageUrl = "",
    femaleImageUrl = "",
    status = "pending",
    createdAt = null,
    updatedAt = null,
    approvedAt = null,
    adminNote = "",
    submittedBy = null,
  } = doc;

  const sanitizedSubmittedBy = submittedBy && typeof submittedBy === "object"
    ? {
        name: normalizeNullableString(submittedBy.name),
        email: normalizeNullableString(submittedBy.email),
        phone: normalizeNullableString(submittedBy.phone),
      }
    : undefined;

  return {
    id: _id ? _id.toString() : undefined,
    coupleNames,
    brideName,
    groomName,
    story,
    rating,
    marriageDate: toIsoOrNull(marriageDate),
    weddingCity,
    heroImageUrl,
    maleImageUrl,
    femaleImageUrl,
    status,
    createdAt,
    updatedAt,
    approvedAt,
    adminNote,
    submittedBy: sanitizedSubmittedBy,
  };
};

const ensureOwnerOrAdmin = (req, res, uid) => {
  if (req.user?.role === "admin") return true;
  if (req.user?.uid && req.user.uid === uid) return true;
  res.status(403).json({ message: "Forbidden" });
  return false;
};

const ensureAdmin = (req, res) => {
  if (req.user?.role === "admin") return true;
  res.status(403).json({ message: "Admin access required" });
  return false;
};

const getNextBiodataNumericId = async () => {
  const total = await BiodataCollection.countDocuments();
  return total + 1;
};

const PREMIUM_USER_FEE_USD = 50;
const PREMIUM_BIODATA_FEE_USD = 10;

// ==================== AUTH (JWT) ====================
app.post("/jwt", async (req, res) => {
  const { email } = req.body;
  const userInfo = await UsersCollection.findOne({ email });
  const uid = userInfo?.uid || "";
  const userType = userInfo?.userType || "basic";
  const role = userInfo?.role || "user";

  const payload = { email, uid, userType, role };

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  // Always set cookies for cross-site: SameSite=None, Secure=true
  res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    })
    .setHeader('Cache-Control', 'no-store')
    .send({ success: true });
});

app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies?.refreshToken;

  if (!refreshToken) {
    return res.status(401).send({ message: "No refresh token" });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Invalid refresh token" });

    const newAccessToken = jwt.sign(
      { email: decoded.email, uid: decoded.uid, role: decoded.role },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    res
      .cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/",
      })
      .setHeader('Cache-Control', 'no-store')
      .send({ success: true });
  });
});

app.post("/logout", (req, res) => {
  res
    .clearCookie("accessToken", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    })
    .clearCookie("refreshToken", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    })
    .setHeader('Cache-Control', 'no-store')
    .send({ success: true });
});

const verifyToken = (req, res, next) => {
  const token = req.cookies?.accessToken;
  if (!token) {
    return res.status(401).send({ message: "Unauthorized Access" });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      res.setHeader('Cache-Control', 'no-store');
      return res.status(403).send({ message: "Access Token Expired or Invalid" });
    }
    req.user = decoded;
    next();
  });
};

// ==================== PUBLIC ROUTES ====================
app.get("/", (req, res) => {
  res.send("🚀Porinity server is running...");
});

app.get("/stats/biodata", async (req, res) => {
  try {
    const [total, female, male] = await Promise.all([
      BiodataCollection.countDocuments({}),
      BiodataCollection.countDocuments({ biodataType: { $regex: /^female$/i } }),
      BiodataCollection.countDocuments({ biodataType: { $regex: /^male$/i } }),
    ]);

    res.json({
      total,
      female,
      male,
    });
  } catch (err) {
    console.error("Error fetching biodata stats:", err);
    res.status(500).json({ message: "Failed to load biodata stats" });
  }
});

app.get("/biodata", async (req, res) => {
  try {
    const {
      page = "1",
      limit = "15",
      type,
      minAge,
      maxAge,
      division,
      searchId,
    } = req.query ?? {};

    const requestedPage = Math.max(parseInt(page, 10) || 1, 1);
    const perPage = Math.min(Math.max(parseInt(limit, 10) || 15, 1), 100);

    const filter = {};

    if (type && type.toLowerCase() !== "all") {
      filter.biodataType = new RegExp(`^${type}$`, "i");
    }

    const ageQuery = {};
    const minAgeNumber = Number(minAge);
    const maxAgeNumber = Number(maxAge);

    if (Number.isFinite(minAgeNumber) && !Number.isNaN(minAgeNumber)) {
      ageQuery.$gte = minAgeNumber;
    }

    if (Number.isFinite(maxAgeNumber) && !Number.isNaN(maxAgeNumber)) {
      ageQuery.$lte = maxAgeNumber;
    }

    if (Object.keys(ageQuery).length) {
      filter.age = ageQuery;
    }

    if (division && division.toLowerCase() !== "all") {
      filter.permanentDivision = new RegExp(`^${division}$`, "i");
    }

    if (searchId) {
      filter.biodataId = new RegExp(searchId, "i");
    }

    const total = await BiodataCollection.countDocuments(filter);
    const totalPages = Math.max(1, Math.ceil(total / perPage));
    const safePage = Math.min(requestedPage, totalPages);
    const skip = (safePage - 1) * perPage;

    const records = await BiodataCollection.find(filter)
      .sort({ createdAt: -1, numericBiodataId: -1 })
      .skip(skip)
      .limit(perPage)
      .toArray();

    res.json({
      data: records.map((item) => sanitizeBiodata(item)),
      pagination: {
        total,
        page: safePage,
        limit: perPage,
        totalPages,
        hasNext: safePage < totalPages,
        hasPrev: safePage > 1,
      },
    });
  } catch (err) {
    console.error("Error fetching biodata list:", err);
    res.status(500).json({ message: "Failed to fetch biodata" });
  }
});

app.get("/biodata/premium", async (req, res) => {
  try {
    const { limit = "6" } = req.query ?? {};
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 6, 1), 24);

    // Use aggregation with $match and $sample for random selection
    const records = await BiodataCollection.aggregate([
      { $match: { premiumStatus: "approved", isPublished: { $ne: false } } },
      { $sample: { size: safeLimit } },
    ]).toArray();

    res.json({
      data: records.map((item) => sanitizeBiodata(item)),
      meta: {
        count: records.length,
      },
    });
  } catch (err) {
    console.error("Error fetching premium biodata list:", err);
    res.status(500).json({ message: "Failed to fetch premium biodata" });
  }
});

app.get("/biodata/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const doc = await BiodataCollection.findOne({ biodataId: id });
    if (!doc) return res.status(404).json({ message: "Biodata not found" });
    res.json(sanitizeBiodata(doc));
  } catch (err) {
    console.error("Error fetching biodata by id:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/success-stories", async (req, res) => {
  try {
    const { limit = "12", status = "approved" } = req.query ?? {};
    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 12, 1), 60);
    const normalizedStatus = normalizeString(status).toLowerCase() || "approved";

    const filter = (() => {
      if (normalizedStatus === "all") {
        return { status: { $ne: "rejected" } };
      }
      if (normalizedStatus === "approved") {
        return {
          $or: [
            { status: "approved" },
            { status: { $exists: false } },
          ],
        };
      }
      return { status: normalizedStatus };
    })();

    const stories = await SuccessStoriesCollection.find(filter)
      .sort({ approvedAt: -1, createdAt: -1 })
      .limit(safeLimit)
      .toArray();

    res.json(stories.map((item) => sanitizeSuccessStory(item)));
  } catch (err) {
    console.error("Error fetching success stories:", err);
    res.status(500).json({ message: "Failed to load success stories" });
  }
});

app.post("/success-stories", async (req, res) => {
  try {
    const {
      brideName,
      groomName,
      coupleNames,
      story,
      marriageDate,
      weddingCity,
      rating,
      heroImageUrl,
      maleImageUrl,
      femaleImageUrl,
      submitterName,
      submitterEmail,
      submitterPhone,
    } = req.body ?? {};

    const sanitizedBride = normalizeNullableString(brideName);
    const sanitizedGroom = normalizeNullableString(groomName);
    const sanitizedStory = normalizeNullableString(story);
    const sanitizedCity = normalizeNullableString(weddingCity);
    const sanitizedHeroImage = normalizeNullableString(heroImageUrl);
    const sanitizedMaleImage = normalizeNullableString(maleImageUrl);
    const sanitizedFemaleImage = normalizeNullableString(femaleImageUrl);
    const sanitizedSubmitterName = normalizeNullableString(submitterName);
    const normalizedEmail = normalizeString(submitterEmail).toLowerCase();
    const sanitizedPhone = normalizeNullableString(submitterPhone);

    if (sanitizedStory.length < 50) {
      return res.status(400).json({ message: "Please share a story with at least 50 characters" });
    }

    if (!normalizedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ message: "A valid contact email is required" });
    }

    const normalizedMarriageDate = normalizeString(marriageDate);
    let marriageDateValue = null;
    if (normalizedMarriageDate) {
      const parsed = new Date(normalizedMarriageDate);
      if (Number.isNaN(parsed.getTime())) {
        return res.status(400).json({ message: "Provide a valid wedding date" });
      }
      marriageDateValue = parsed;
    }

    const ratingNumber = Number(rating);
    const safeRating = Number.isFinite(ratingNumber)
      ? Math.min(Math.max(Math.round(ratingNumber), 1), 5)
      : 5;

    const inferredCoupleNames = normalizeNullableString(coupleNames)
      || [sanitizedGroom, sanitizedBride].filter(Boolean).join(" & ");

    if (!inferredCoupleNames) {
      return res.status(400).json({ message: "Please include the couple names" });
    }

    const now = new Date();
    const doc = {
      coupleNames: inferredCoupleNames,
      brideName: sanitizedBride,
      groomName: sanitizedGroom,
      story: sanitizedStory,
      rating: safeRating,
      marriageDate: marriageDateValue,
      weddingCity: sanitizedCity,
      heroImageUrl: sanitizedHeroImage,
      maleImageUrl: sanitizedMaleImage,
      femaleImageUrl: sanitizedFemaleImage,
      status: "pending",
      createdAt: now,
      updatedAt: now,
      approvedAt: null,
      adminNote: "",
      submittedBy: {
        name: sanitizedSubmitterName,
        email: normalizedEmail,
        phone: sanitizedPhone,
      },
    };

    const result = await SuccessStoriesCollection.insertOne(doc);

    res.status(201).json({
      success: true,
      message: "Thank you for sharing your journey. Our admin team will review it shortly.",
      id: result.insertedId?.toString() || null,
    });
  } catch (err) {
    console.error("Error submitting success story:", err);
    res.status(500).json({ message: "Failed to submit success story" });
  }
});

// ==================== USER ROUTES ====================
app.post("/register", async (req, res) => {
  const { email, uid, role, userType } = req.body ?? {};

  const existingUser = await UsersCollection.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = {
    email,
    uid,
    userType: userType || "basic",
    role: role || "user",
    premiumUserStatus: "none",
    premiumUserRequestedAt: null,
    premiumUserApprovedAt: null,
    premiumUserPayment: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
  await UsersCollection.insertOne(newUser);

  res.status(201).json({
    success: true,
    user: {
      email,
      uid,
      userType: newUser.userType,
      role: newUser.role,
    },
  });
});

app.get("/users/:uid", async (req, res) => {
  const { uid } = req.params;

  if (!uid) {
    return res.status(400).json({ message: "UID is required" });
  }

  try {
    const user = await UsersCollection.findOne({ uid });
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json(user);
  } catch (err) {
    console.error("Error fetching user by uid:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/users/profile", verifyToken, async (req, res) => {
  try {
    const uidFromToken = req.user?.uid;
    const roleFromToken = req.user?.role;

    const {
      uid,
      email,
      displayName,
      photoURL,
      phoneNumber,
      address,
      bio,
    } = req.body ?? {};

    if (!uid) {
      return res.status(400).json({ message: "uid is required" });
    }

    if (uidFromToken !== uid && roleFromToken !== "admin") {
      return res
        .status(403)
        .json({ message: "You can only update your own profile" });
    }

    const existing = await UsersCollection.findOne({ uid });
    if (!existing) {
      return res.status(404).json({ message: "User not found" });
    }

    const sanitizedDisplayName = normalizeNullableString(displayName);
    if (!sanitizedDisplayName) {
      return res
        .status(400)
        .json({ message: "Display name is required" });
    }

    const normalizedEmail = normalizeString(email || existing.email).toLowerCase();
    const now = new Date();

    const updateDoc = {
      email: normalizedEmail || existing.email || "",
      displayName: sanitizedDisplayName,
      photoURL: normalizeNullableString(photoURL),
      phoneNumber: normalizeNullableString(phoneNumber),
      address: normalizeNullableString(address),
      bio: normalizeNullableString(bio),
      updatedAt: now,
      profileUpdatedAt: now,
    };

    const result = await UsersCollection.updateOne(
      { uid },
      { $set: updateDoc }
    );

    if (!result.modifiedCount) {
      return res.json({
        success: true,
        message: "Profile already up to date",
      });
    }

    res.json({ success: true, message: "Profile updated successfully" });
  } catch (err) {
    console.error("Error updating user profile:", err);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

app.post("/users/profile", verifyToken, async (req, res) => {
  try {
    const uidFromToken = req.user?.uid;
    const roleFromToken = req.user?.role;
    const userTypeFromToken = req.user?.userType;

    const {
      uid,
      email,
      displayName,
      photoURL,
      phoneNumber,
      address,
      bio,
    } = req.body ?? {};

    if (!uid) {
      return res.status(400).json({ message: "uid is required" });
    }

    if (uidFromToken !== uid && roleFromToken !== "admin") {
      return res
        .status(403)
        .json({ message: "You can only update your own profile" });
    }

    const sanitizedDisplayName = normalizeNullableString(displayName);
    if (!sanitizedDisplayName) {
      return res
        .status(400)
        .json({ message: "Display name is required" });
    }

    const existing = await UsersCollection.findOne({ uid });
    const now = new Date();

    const normalizedEmail = normalizeString(
      email || existing?.email || req.user?.email
    ).toLowerCase();

    const baseRole = existing?.role || "user";
    const baseUserType = existing?.userType || userTypeFromToken || "basic";

    const updatePayload = {
      email: normalizedEmail || existing?.email || "",
      displayName: sanitizedDisplayName,
      photoURL: normalizeNullableString(photoURL),
      phoneNumber: normalizeNullableString(phoneNumber),
      address: normalizeNullableString(address),
      bio: normalizeNullableString(bio),
      updatedAt: now,
      profileUpdatedAt: now,
    };

    const result = await UsersCollection.updateOne(
      { uid },
      {
        $set: updatePayload,
        $setOnInsert: {
          uid,
          role: baseRole,
          userType: baseUserType,
          createdAt: existing?.createdAt || now,
        },
      },
      { upsert: true }
    );

    const message = existing
      ? "Profile saved successfully"
      : "Profile created successfully";

    res.status(existing ? 200 : 201).json({ success: true, message });
  } catch (err) {
    console.error("Error saving user profile:", err);
    res.status(500).json({ message: "Failed to save profile" });
  }
});

app.post("/users/premium-request", verifyToken, async (req, res) => {
  try {
    const uid = req.user?.uid;
    if (!uid) {
      return res.status(403).json({ message: "User context missing" });
    }

    const {
      amount,
      currency,
      paymentProvider,
      paymentMethod,
      cardLast4,
      transactionId,
    } = req.body ?? {};

    const user = await UsersCollection.findOne({ uid });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.userType === "premium") {
      return res.json({ success: true, message: "You are already a premium user" });
    }

    if (user.premiumUserStatus === "pending") {
      return res.json({ success: true, message: "Premium user request already pending" });
    }

    const amountNumber = Number(amount);
    if (!Number.isFinite(amountNumber) || amountNumber <= 0) {
      return res.status(400).json({ message: "amount must be a positive number" });
    }

    if (amountNumber !== PREMIUM_USER_FEE_USD) {
      return res.status(400).json({ message: `Premium user upgrade costs $${PREMIUM_USER_FEE_USD}` });
    }

    const sanitizedCard = String(cardLast4 || "").replace(/\D/g, "").slice(-4);
    if (sanitizedCard.length !== 4) {
      return res.status(400).json({ message: "Provide the last four digits of the payment card" });
    }

    const now = new Date();

    await UsersCollection.updateOne(
      { uid },
      {
        $set: {
          premiumUserStatus: "pending",
          premiumUserRequestedAt: now,
          premiumUserApprovedAt: null,
          premiumUserPayment: {
            amount: amountNumber,
            currency: currency || "USD",
            paymentProvider: paymentProvider || "stripe",
            paymentMethod: paymentMethod || "card",
            cardLast4: sanitizedCard,
            transactionId: transactionId || null,
            status: "pending",
          },
          updatedAt: now,
        },
      }
    );

    res.json({ success: true, message: "Premium user request submitted for review" });
  } catch (err) {
    console.error("Error submitting premium user request:", err);
    res.status(500).json({ message: "Failed to submit premium user request" });
  }
});

// ==================== ADMIN ROUTES ====================
app.get("/admin/overview", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const [
      totalBiodata,
      maleBiodata,
      femaleBiodata,
      premiumBiodata,
      pendingPremium,
      premiumUsers,
      pendingPremiumUsers,
      pendingContactRequests,
      openContactMessages,
      pendingSuccessStories,
      contactRevenueAgg,
      premiumBiodataRevenueAgg,
      premiumUserRevenueAgg,
    ] = await Promise.all([
      BiodataCollection.countDocuments({}),
      BiodataCollection.countDocuments({
        biodataType: { $regex: /^male$/i },
      }),
      BiodataCollection.countDocuments({
        biodataType: { $regex: /^female$/i },
      }),
      BiodataCollection.countDocuments({ premiumStatus: "approved" }),
      BiodataCollection.countDocuments({ premiumStatus: "pending" }),
      UsersCollection.countDocuments({ userType: "premium" }),
      UsersCollection.countDocuments({ premiumUserStatus: "pending" }),
      ContactRequestsCollection.countDocuments({ status: "pending" }),
      ContactMessagesCollection.countDocuments({
        status: { $in: ["new", "in_progress"] },
      }),
      SuccessStoriesCollection.countDocuments({
        status: { $in: ["pending", "under_review"] },
      }),
      ContactRequestsCollection.aggregate([
        { $match: { status: "approved" } },
        {
          $project: {
            amount: {
              $toDouble: {
                $ifNull: ["$amount", 0],
              },
            },
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
      ]).toArray(),
      BiodataCollection.aggregate([
        {
          $match: {
            premiumStatus: "approved",
            "premiumPayment.amount": { $exists: true },
          },
        },
        {
          $project: {
            amount: {
              $toDouble: {
                $ifNull: ["$premiumPayment.amount", 0],
              },
            },
            status: "$premiumPayment.status",
          },
        },
        {
          $match: {
            amount: { $gt: 0 },
            $or: [
              { status: "approved" },
              { status: { $exists: false } },
            ],
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
      ]).toArray(),
      UsersCollection.aggregate([
        {
          $match: {
            premiumUserStatus: "approved",
            "premiumUserPayment.amount": { $exists: true },
          },
        },
        {
          $project: {
            amount: {
              $toDouble: {
                $ifNull: ["$premiumUserPayment.amount", 0],
              },
            },
            status: "$premiumUserPayment.status",
          },
        },
        {
          $match: {
            amount: { $gt: 0 },
            $or: [
              { status: "approved" },
              { status: { $exists: false } },
            ],
          },
        },
        {
          $group: {
            _id: null,
            total: { $sum: "$amount" },
            count: { $sum: 1 },
          },
        },
      ]).toArray(),
    ]);

      const contactRevenueStats = contactRevenueAgg?.[0] || { total: 0, count: 0 };
      const premiumBiodataRevenueStats = premiumBiodataRevenueAgg?.[0] || { total: 0, count: 0 };
      const premiumUserRevenueStats = premiumUserRevenueAgg?.[0] || { total: 0, count: 0 };
      const totalRevenue =
        (contactRevenueStats.total || 0) +
        (premiumBiodataRevenueStats.total || 0) +
        (premiumUserRevenueStats.total || 0);

    res.json({
      totals: {
        totalBiodata,
        maleBiodata,
        femaleBiodata,
        premiumBiodata,
        pendingPremium,
        premiumUsers,
        pendingPremiumUsers,
        pendingContactRequests,
        pendingContactMessages: openContactMessages,
        pendingSuccessStories,
        approvedContactRequests: contactRevenueStats.count || 0,
      },
      revenue: {
        totalRevenue,
        contactRevenue: contactRevenueStats.total || 0,
        premiumBiodataRevenue: premiumBiodataRevenueStats.total || 0,
        premiumUserRevenue: premiumUserRevenueStats.total || 0,
        contactRevenueCount: contactRevenueStats.count || 0,
        premiumBiodataRevenueCount: premiumBiodataRevenueStats.count || 0,
        premiumUserRevenueCount: premiumUserRevenueStats.count || 0,
      },
      chart: {
        segments: [
          { label: "Total Biodata", value: totalBiodata },
          { label: "Male Biodata", value: maleBiodata },
          { label: "Female Biodata", value: femaleBiodata },
          { label: "Premium Biodata", value: premiumBiodata },
        ],
      },
    });
  } catch (err) {
    console.error("Error fetching admin overview:", err);
    res.status(500).json({ message: "Failed to load admin overview" });
  }
});

app.get("/admin/users", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const { search = "", page = "1", limit = "20" } = req.query ?? {};

    const pageNumber = Math.max(parseInt(page, 10) || 1, 1);
    const perPage = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 100);
    const skip = (pageNumber - 1) * perPage;

    const trimmedSearch = normalizeString(search);
    const filter = {};

    if (trimmedSearch) {
      const regex = new RegExp(trimmedSearch, "i");
      filter.$or = [{ displayName: regex }, { email: regex }];
    }

    const total = await UsersCollection.countDocuments(filter);

    const rows = await UsersCollection.aggregate([
      { $match: filter },
      {
        $lookup: {
          from: "BiodataCollection",
          localField: "uid",
          foreignField: "uid",
          as: "biodata",
        },
      },
      {
        $unwind: {
          path: "$biodata",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          uid: 1,
          email: 1,
          displayName: 1,
          role: 1,
          userType: 1,
          createdAt: 1,
          biodataId: "$biodata.biodataId",
          premiumStatus: "$biodata.premiumStatus",
          premiumRequestedAt: "$biodata.premiumRequestedAt",
        },
      },
      { $sort: { createdAt: -1 } },
      { $skip: skip },
      { $limit: perPage },
    ]).toArray();

    res.json({
      data: rows,
      pagination: {
        total,
        page: pageNumber,
        limit: perPage,
        totalPages: Math.max(1, Math.ceil(total / perPage)),
      },
    });
  } catch (err) {
    console.error("Error fetching users for admin:", err);
    res.status(500).json({ message: "Failed to load users" });
  }
});

app.post("/admin/users/:uid/make-admin", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  const { uid } = req.params;

  if (!uid) {
    return res.status(400).json({ message: "uid is required" });
  }

  try {
    const result = await UsersCollection.updateOne(
      { uid },
      { $set: { role: "admin", updatedAt: new Date() } }
    );

    if (!result.matchedCount) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ success: true, message: "User promoted to admin" });
  } catch (err) {
    console.error("Error promoting user to admin:", err);
    res.status(500).json({ message: "Failed to promote user" });
  }
});

app.post("/admin/users/:uid/make-premium", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  const { uid } = req.params;

  if (!uid) {
    return res.status(400).json({ message: "uid is required" });
  }

  try {
    const user = await UsersCollection.findOne({ uid });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.userType === "premium") {
      return res.json({ success: true, message: "User already has premium access" });
    }

    const now = new Date();

    await UsersCollection.updateOne(
      { uid },
      {
        $set: {
          userType: "premium",
          premiumUserStatus: "approved",
          premiumUserApprovedAt: now,
          updatedAt: now,
        },
      }
    );

    res.json({ success: true, message: "User promoted to premium" });
  } catch (err) {
    console.error("Error promoting user to premium:", err);
    res.status(500).json({ message: "Failed to promote user" });
  }
});

app.get("/admin/premium-requests", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const requests = await BiodataCollection.aggregate([
      { $match: { premiumStatus: "pending" } },
      {
        $lookup: {
          from: "Users",
          localField: "uid",
          foreignField: "uid",
          as: "user",
        },
      },
      {
        $unwind: {
          path: "$user",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          biodataId: 1,
          name: "$name",
          email: { $ifNull: ["$user.email", "$contactEmail", ""] },
          uid: 1,
          requestedAt: "$premiumRequestedAt",
          amount: "$premiumPayment.amount",
          currency: "$premiumPayment.currency",
          cardLast4: "$premiumPayment.cardLast4",
          paymentMethod: "$premiumPayment.paymentMethod",
          paymentProvider: "$premiumPayment.paymentProvider",
        },
      },
      { $sort: { premiumRequestedAt: 1, biodataId: 1 } },
    ]).toArray();

    res.json(requests);
  } catch (err) {
    console.error("Error fetching premium requests:", err);
    res.status(500).json({ message: "Failed to load premium requests" });
  }
});

app.get("/admin/premium-user-requests", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const requests = await UsersCollection.find({ premiumUserStatus: "pending" })
      .sort({ premiumUserRequestedAt: 1, createdAt: 1 })
      .toArray();

    res.json(
      requests.map((item) => ({
        uid: item.uid,
        email: item.email,
        displayName: item.displayName || null,
        requestedAt: item.premiumUserRequestedAt || null,
        amount: item.premiumUserPayment?.amount || null,
        currency: item.premiumUserPayment?.currency || "USD",
        paymentMethod: item.premiumUserPayment?.paymentMethod || null,
        paymentProvider: item.premiumUserPayment?.paymentProvider || null,
        cardLast4: item.premiumUserPayment?.cardLast4 || null,
      }))
    );
  } catch (err) {
    console.error("Error fetching premium user requests:", err);
    res.status(500).json({ message: "Failed to load premium user requests" });
  }
});

app.post(
  "/admin/premium-user-requests/:uid/approve",
  verifyToken,
  async (req, res) => {
    if (!ensureAdmin(req, res)) return;

    const { uid } = req.params;
    if (!uid) {
      return res.status(400).json({ message: "uid is required" });
    }

    try {
      const user = await UsersCollection.findOne({ uid });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      if (user.userType === "premium") {
        return res.json({ success: true, message: "User is already premium" });
      }

      const now = new Date();

      await UsersCollection.updateOne(
        { uid },
        {
          $set: {
            userType: "premium",
            premiumUserStatus: "approved",
            premiumUserApprovedAt: now,
            updatedAt: now,
            "premiumUserPayment.status": "approved",
            "premiumUserPayment.approvedAt": now,
          },
        }
      );

      res.json({ success: true, message: "User promoted to premium" });
    } catch (err) {
      console.error("Error approving premium user request:", err);
      res.status(500).json({ message: "Failed to approve premium user request" });
    }
  }
);

app.post(
  "/admin/premium-requests/:biodataId/approve",
  verifyToken,
  async (req, res) => {
    if (!ensureAdmin(req, res)) return;

    const { biodataId } = req.params;

    if (!biodataId) {
      return res.status(400).json({ message: "biodataId is required" });
    }

    try {
      const biodata = await BiodataCollection.findOne({ biodataId });
      if (!biodata) {
        return res.status(404).json({ message: "Biodata not found" });
      }

      if (biodata.premiumStatus === "approved") {
        return res.json({ success: true, message: "Biodata already premium" });
      }

      const now = new Date();

      await BiodataCollection.updateOne(
        { biodataId },
        {
          $set: {
            premiumStatus: "approved",
            premiumReviewedAt: now,
            premiumRequestedAt: biodata.premiumRequestedAt || now,
            premiumBadgeActivatedAt: now,
            updatedAt: now,
            "premiumPayment.status": "approved",
            "premiumPayment.approvedAt": now,
          },
        }
      );

      res.json({ success: true, message: "Premium request approved" });
    } catch (err) {
      console.error("Error approving premium request:", err);
      res.status(500).json({ message: "Failed to approve premium request" });
    }
  }
);

app.get("/admin/contact-requests", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const { status = "pending" } = req.query ?? {};
    const trimmedStatus = normalizeString(status);

    const filter = {};
    if (trimmedStatus && trimmedStatus.toLowerCase() !== "all") {
      filter.status = trimmedStatus.toLowerCase();
    }

    const requests = await ContactRequestsCollection.aggregate([
      { $match: filter },
      {
        $lookup: {
          from: "Users",
          localField: "requesterUid",
          foreignField: "uid",
          as: "user",
        },
      },
      {
        $unwind: {
          path: "$user",
          preserveNullAndEmptyArrays: true,
        },
      },
      {
        $project: {
          _id: 1,
          biodataId: 1,
          requesterUid: 1,
          requesterEmail: 1,
          status: 1,
          amount: 1,
          currency: 1,
          createdAt: 1,
          name: { $ifNull: ["$user.displayName", "$biodataName", ""] },
          email: { $ifNull: ["$user.email", "$requesterEmail", ""] },
        },
      },
      { $sort: { createdAt: -1 } },
    ]).toArray();

    res.json(
      requests.map((item) => ({
        id: item._id?.toString(),
        biodataId: item.biodataId,
        name: item.name,
        email: item.email,
        status: item.status,
        amount: item.amount,
        currency: item.currency,
        createdAt: item.createdAt,
      }))
    );
  } catch (err) {
    console.error("Error fetching contact requests for admin:", err);
    res.status(500).json({ message: "Failed to load contact requests" });
  }
});

app.post(
  "/admin/contact-requests/:id/approve",
  verifyToken,
  async (req, res) => {
    if (!ensureAdmin(req, res)) return;

    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ message: "id is required" });
    }

    let objectId;
    try {
      objectId = new ObjectId(id);
    } catch (err) {
      return res.status(400).json({ message: "Invalid request id" });
    }

    try {
      const requestDoc = await ContactRequestsCollection.findOne({
        _id: objectId,
      });

      if (!requestDoc) {
        return res.status(404).json({ message: "Contact request not found" });
      }

      if (requestDoc.status === "approved") {
        return res.json({
          success: true,
          message: "Contact request already approved",
        });
      }

      await ContactRequestsCollection.updateOne(
        { _id: objectId },
        {
          $set: {
            status: "approved",
            updatedAt: new Date(),
          },
        }
      );

      res.json({ success: true, message: "Contact request approved" });
    } catch (err) {
      console.error("Error approving contact request:", err);
      res.status(500).json({ message: "Failed to approve contact request" });
    }
  }
);

app.get("/admin/success-stories", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const { status = "pending" } = req.query ?? {};
    const normalizedStatus = normalizeString(status).toLowerCase();
    const filter = {};

    if (normalizedStatus && normalizedStatus !== "all") {
      if (normalizedStatus === "pending") {
        filter.$or = [
          { status: "pending" },
          { status: { $exists: false } },
        ];
      } else {
        filter.status = normalizedStatus;
      }
    }

    const stories = await SuccessStoriesCollection.find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    res.json(stories.map((item) => sanitizeSuccessStory(item)));
  } catch (err) {
    console.error("Error fetching success stories:", err);
    res.status(500).json({ message: "Failed to load success stories" });
  }
});

app.patch("/admin/success-stories/:id/status", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  const { id } = req.params;
  const { status, adminNote } = req.body ?? {};

  if (!id) {
    return res.status(400).json({ message: "Story id is required" });
  }

  let objectId;
  try {
    objectId = new ObjectId(id);
  } catch (err) {
    return res.status(400).json({ message: "Invalid story id" });
  }

  const normalizedStatus = normalizeString(status).toLowerCase();
  const allowed = new Set(["pending", "under_review", "approved", "rejected"]);

  if (!allowed.has(normalizedStatus)) {
    return res.status(400).json({ message: "Invalid status value" });
  }

  const now = new Date();
  const updateDoc = {
    status: normalizedStatus,
    updatedAt: now,
    approvedAt: normalizedStatus === "approved" ? now : null,
  };

  if (typeof adminNote === "string") {
    updateDoc.adminNote = normalizeNullableString(adminNote);
  }

  try {
    const { value } = await SuccessStoriesCollection.findOneAndUpdate(
      { _id: objectId },
      { $set: updateDoc },
      { returnDocument: "after" }
    );

    if (!value) {
      return res.status(404).json({ message: "Success story not found" });
    }

    res.json({
      success: true,
      message: "Success story updated",
      story: sanitizeSuccessStory(value),
    });
  } catch (err) {
    console.error("Error updating success story status:", err);
    res.status(500).json({ message: "Failed to update success story" });
  }
});

// ==================== BIODATA MANAGEMENT ====================
app.get("/biodata/user/:uid", verifyToken, async (req, res) => {
  const { uid } = req.params;
  if (!ensureOwnerOrAdmin(req, res, uid)) return;

  const biodata = await BiodataCollection.findOne({ uid });
  if (!biodata) {
    return res.status(404).json({ message: "Biodata not found" });
  }

  res.json(sanitizeBiodata(biodata, { includePayment: true }));
});

app.post("/biodata", verifyToken, async (req, res) => {
  const uid = req.user?.uid;
  const email = req.user?.email?.toLowerCase();

  if (!uid || !email) {
    return res.status(403).json({ message: "User context missing" });
  }

  const {
    biodataType,
    name,
    profileImage,
    dateOfBirth,
    height,
    weight,
    age,
    occupation,
    race,
    fatherName,
    motherName,
    permanentDivision,
    presentDivision,
    expectedPartnerAge,
    expectedPartnerHeight,
    expectedPartnerWeight,
    mobileNumber,
    about,
  } = req.body ?? {};

  const requiredFields = [
    ["biodataType", biodataType, "Biodata type is required"],
    ["name", name, "Name is required"],
    ["dateOfBirth", dateOfBirth, "Date of birth is required"],
    ["height", height, "Height is required"],
    ["weight", weight, "Weight is required"],
    ["age", age, "Age is required"],
    ["occupation", occupation, "Occupation is required"],
    ["race", race, "Race/complexion is required"],
    ["permanentDivision", permanentDivision, "Permanent division is required"],
    ["presentDivision", presentDivision, "Present division is required"],
    [
      "expectedPartnerHeight",
      expectedPartnerHeight,
      "Expected partner height is required",
    ],
    [
      "expectedPartnerWeight",
      expectedPartnerWeight,
      "Expected partner weight is required",
    ],
    ["mobileNumber", mobileNumber, "Mobile number is required"],
  ];

  for (const [, value, message] of requiredFields) {
    if (!value) {
      return res.status(400).json({ message });
    }
  }

  const ageNumber = Number(age);
  if (!Number.isFinite(ageNumber) || ageNumber < 18) {
    return res
      .status(400)
      .json({ message: "Age must be a number and at least 18" });
  }

  const baseDoc = {
    biodataType,
    name,
    profileImage: profileImage || "",
    dateOfBirth,
    height,
    weight,
    age: ageNumber,
    occupation,
    race,
    fatherName: fatherName || "",
    motherName: motherName || "",
    permanentDivision,
    permanentAddress: permanentDivision,
    presentDivision,
    expectedPartnerAge: expectedPartnerAge || "",
    expectedPartnerHeight,
    expectedPartnerWeight,
    contactEmail: email,
    mobileNumber: String(mobileNumber),
    about: about || "",
    uid,
    updatedAt: new Date(),
    isPublished: true,
  };

  const existing = await BiodataCollection.findOne({ uid });

  if (existing) {
    if (!existing.numericBiodataId) {
      const numeric = extractNumericId(existing.biodataId);
      await BiodataCollection.updateOne(
        { _id: existing._id },
        { $set: { numericBiodataId: numeric } }
      );
      existing.numericBiodataId = numeric;
    }

    const numericId =
      existing.numericBiodataId || extractNumericId(existing.biodataId) || 1;
    const canonicalId = existing.biodataId?.startsWith("PRNT-")
      ? existing.biodataId
      : `PRNT-${numericId}`;

    const updateDoc = {
      ...baseDoc,
      biodataId: canonicalId,
      numericBiodataId: numericId,
      premiumStatus: existing.premiumStatus || "none",
      premiumRequestedAt: existing.premiumRequestedAt || null,
      premiumReviewedAt: existing.premiumReviewedAt || null,
      premiumBadgeActivatedAt: existing.premiumBadgeActivatedAt || null,
      premiumPayment: existing.premiumPayment || null,
      createdAt: existing.createdAt || new Date(),
    };

    const { value } = await BiodataCollection.findOneAndUpdate(
      { _id: existing._id },
      { $set: updateDoc },
      { returnDocument: "after" }
    );

    return res.json({
      success: true,
      message: "Biodata updated successfully",
      biodata: sanitizeBiodata(value),
    });
  }

  const nextNumericId = await getNextBiodataNumericId();
  const biodataId = `PRNT-${nextNumericId}`;

  const newDoc = {
    ...baseDoc,
    biodataId,
    numericBiodataId: nextNumericId,
    premiumStatus: "none",
    premiumRequestedAt: null,
    premiumReviewedAt: null,
    premiumBadgeActivatedAt: null,
    premiumPayment: null,
    createdAt: new Date(),
  };

  await BiodataCollection.insertOne(newDoc);

  res.status(201).json({
    success: true,
    message: "Biodata created successfully",
    biodata: sanitizeBiodata(newDoc),
  });
});

app.post(
  "/biodata/:id/premium-request",
  verifyToken,
  async (req, res) => {
    const { id } = req.params;

    const biodata = await BiodataCollection.findOne({ biodataId: id });
    if (!biodata) {
      return res.status(404).json({ message: "Biodata not found" });
    }

    if (!ensureOwnerOrAdmin(req, res, biodata.uid)) return;

    if (biodata.premiumStatus === "approved") {
      return res
        .status(400)
        .json({ message: "This biodata is already premium" });
    }

    if (biodata.premiumStatus === "pending") {
      return res.json({
        success: true,
        message: "Premium request already pending review",
      });
    }

    const {
      amount,
      currency,
      paymentProvider,
      paymentMethod,
      cardLast4,
      transactionId,
    } = req.body ?? {};

    const amountNumber = Number(amount);
    if (!Number.isFinite(amountNumber) || amountNumber <= 0) {
      return res.status(400).json({ message: "amount must be a positive number" });
    }

    if (amountNumber !== PREMIUM_BIODATA_FEE_USD) {
      return res
        .status(400)
        .json({ message: `Premium biodata upgrade costs $${PREMIUM_BIODATA_FEE_USD}` });
    }

    const sanitizedCard = String(cardLast4 || "").replace(/\D/g, "").slice(-4);
    if (sanitizedCard.length !== 4) {
      return res.status(400).json({ message: "Provide the last four digits of the payment card" });
    }

    const now = new Date();

    await BiodataCollection.updateOne(
      { _id: biodata._id },
      {
        $set: {
          premiumStatus: "pending",
          premiumRequestedAt: now,
          premiumReviewedAt: null,
          premiumPayment: {
            amount: amountNumber,
            currency: currency || "USD",
            paymentProvider: paymentProvider || "stripe",
            paymentMethod: paymentMethod || "card",
            cardLast4: sanitizedCard,
            transactionId: transactionId || null,
            status: "pending",
            requestedAt: now,
          },
          premiumBadgeActivatedAt: null,
          updatedAt: now,
        },
      }
    );

    res.json({
      success: true,
      message: "Premium request submitted for review",
    });
  }
);

// ==================== FAVORITES ====================
app.post("/favorites", verifyToken, async (req, res) => {
  try {
    const uidFromToken = req.user?.uid;
    const { biodataId, uid } = req.body ?? {};

    if (!uidFromToken || uidFromToken !== uid) {
      return res
        .status(403)
        .json({ message: "You can only modify your own favorites" });
    }

    if (!uid || !biodataId) {
      return res
        .status(400)
        .json({ message: "uid and biodataId are required" });
    }

    const [user, biodata] = await Promise.all([
      UsersCollection.findOne({ uid }),
      BiodataCollection.findOne({ biodataId: String(biodataId) }),
    ]);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!biodata) {
      return res.status(404).json({ message: "Biodata not found" });
    }

    const updateResult = await UsersCollection.updateOne(
      { uid },
      {
        $addToSet: {
          favorites: String(biodataId),
        },
      }
    );

    if (!updateResult.modifiedCount) {
      return res.status(200).json({
        success: true,
        message: "Biodata already present in favorites",
      });
    }

    res.status(200).json({
      success: true,
      message: "Biodata added to favorites",
    });
  } catch (err) {
    console.error("Error adding favorite biodata:", err);
    res.status(500).json({ message: "Failed to add favorite" });
  }
});

app.get("/favorites/:uid", verifyToken, async (req, res) => {
  try {
    const uid = req.params?.uid;

    if (!ensureOwnerOrAdmin(req, res, uid)) return;

    const user = await UsersCollection.findOne(
      { uid },
      { projection: { favorites: 1 } }
    );

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const favorites = Array.isArray(user.favorites) ? user.favorites : [];

    if (!favorites.length) {
      return res.json([]);
    }

    const favoriteBiodata = await BiodataCollection.find(
      { biodataId: { $in: favorites.map(String) } },
      {
        projection: {
          _id: 0,
          name: 1,
          biodataId: 1,
          permanentAddress: 1,
          occupation: 1,
        },
      }
    ).toArray();

    res.json(favoriteBiodata);
  } catch (err) {
    console.error("Error fetching favorite biodatas:", err);
    res.status(500).json({ message: "Failed to fetch favorites" });
  }
});

app.delete("/favorites", verifyToken, async (req, res) => {
  try {
    const uidFromToken = req.user?.uid;
    const { uid, biodataId } = req.body ?? {};

    if (!uidFromToken || uidFromToken !== uid) {
      return res
        .status(403)
        .json({ message: "You can only modify your own favorites" });
    }

    if (!uid || !biodataId) {
      return res
        .status(400)
        .json({ message: "uid and biodataId are required" });
    }

    const updateResult = await UsersCollection.updateOne(
      { uid },
      {
        $pull: {
          favorites: String(biodataId),
        },
      }
    );

    if (!updateResult.matchedCount) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!updateResult.modifiedCount) {
      return res.status(200).json({
        success: true,
        message: "Biodata was not in favorites",
      });
    }

    res.status(200).json({
      success: true,
      message: "Biodata removed from favorites",
    });
  } catch (err) {
    console.error("Error removing favorite biodata:", err);
    res.status(500).json({ message: "Failed to remove favorite" });
  }
});

// ==================== CONTACT MESSAGES ====================
app.post("/contact-messages", async (req, res) => {
  try {
    const {
      name,
      email,
      channel,
      message,
    } = req.body ?? {};

    const sanitizedName = normalizeNullableString(name);
    if (!sanitizedName) {
      return res.status(400).json({ message: "Name is required" });
    }

    const normalizedEmail = normalizeString(email).toLowerCase();
    if (!normalizedEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      return res.status(400).json({ message: "A valid email address is required" });
    }

    const sanitizedMessage = normalizeNullableString(message);
    if (!sanitizedMessage || sanitizedMessage.length < 10) {
      return res.status(400).json({ message: "Please share a message with at least 10 characters" });
    }

    const sanitizedChannel = normalizeNullableString(channel) || "concierge";
    const now = new Date();

    const doc = {
      name: sanitizedName,
      email: normalizedEmail,
      channel: sanitizedChannel.toLowerCase(),
      message: sanitizedMessage,
      status: "new",
      source: "public",
      createdAt: now,
      updatedAt: now,
      resolvedAt: null,
      adminNote: "",
      metadata: {
        userAgent: normalizeNullableString(req.get("user-agent")) || null,
        referer: normalizeNullableString(req.get("referer")) || null,
        ip: normalizeNullableString(req.ip) || null,
      },
    };

    const result = await ContactMessagesCollection.insertOne(doc);

    res.status(201).json({
      success: true,
      message: "Thank you for contacting Porinity. Our concierge team will respond shortly.",
      id: result.insertedId?.toString() || null,
    });
  } catch (err) {
    console.error("Error submitting contact message:", err);
    res.status(500).json({ message: "Failed to submit message" });
  }
});

app.get("/admin/contact-messages", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  try {
    const { status = "new" } = req.query ?? {};
    const normalizedStatus = normalizeString(status).toLowerCase();

    const filter = {};
    if (normalizedStatus && normalizedStatus !== "all") {
      filter.status = normalizedStatus;
    }

    const messages = await ContactMessagesCollection.find(filter)
      .sort({ status: 1, createdAt: -1 })
      .toArray();

    res.json(messages.map((item) => sanitizeContactMessage(item)));
  } catch (err) {
    console.error("Error fetching contact messages:", err);
    res.status(500).json({ message: "Failed to load contact messages" });
  }
});

app.patch("/admin/contact-messages/:id", verifyToken, async (req, res) => {
  if (!ensureAdmin(req, res)) return;

  const { id } = req.params;
  const { status, adminNote } = req.body ?? {};

  if (!id) {
    return res.status(400).json({ message: "Message id is required" });
  }

  let objectId;
  try {
    objectId = new ObjectId(id);
  } catch (err) {
    return res.status(400).json({ message: "Invalid message id" });
  }

  const normalizedStatus = normalizeString(status).toLowerCase();
  const allowedStatuses = new Set(["new", "resolved", "in_progress"]);

  if (!allowedStatuses.has(normalizedStatus)) {
    return res.status(400).json({ message: "Invalid status value" });
  }

  const now = new Date();
  const updateDoc = {
    status: normalizedStatus,
    updatedAt: now,
    resolvedAt: normalizedStatus === "resolved" ? now : null,
  };

  if (typeof adminNote === "string") {
    updateDoc.adminNote = normalizeNullableString(adminNote);
  }

  try {
    const { value } = await ContactMessagesCollection.findOneAndUpdate(
      { _id: objectId },
      { $set: updateDoc },
      { returnDocument: "after" }
    );

    if (!value) {
      return res.status(404).json({ message: "Contact message not found" });
    }

    res.json({
      success: true,
      message: "Contact message updated",
      contactMessage: sanitizeContactMessage(value),
    });
  } catch (err) {
    console.error("Error updating contact message:", err);
    res.status(500).json({ message: "Failed to update contact message" });
  }
});

// ==================== CONTACT REQUESTS ====================
app.post("/contact-requests", verifyToken, async (req, res) => {
  try {
    const uid = req.user?.uid;
    const requesterEmail = req.user?.email?.toLowerCase();

    const {
      biodataId,
      amount,
      currency,
      paymentProvider,
      paymentMethod,
      cardLast4,
      status = "pending",
    } = req.body ?? {};

    if (!uid || !requesterEmail) {
      return res
        .status(403)
        .json({ message: "User context missing for contact request" });
    }

    if (!biodataId) {
      return res
        .status(400)
        .json({ message: "biodataId is required" });
    }

    const amountNumber = Number(amount);
    if (!Number.isFinite(amountNumber) || amountNumber <= 0) {
      return res
        .status(400)
        .json({ message: "amount must be a positive number" });
    }

    const last4Digits = String(cardLast4 || "")
      .replace(/\D/g, "")
      .slice(-4);
    if (last4Digits.length !== 4) {
      return res.status(400).json({
        message: "cardLast4 must contain the last four digits of the card",
      });
    }

    const biodata = await BiodataCollection.findOne({
      biodataId: String(biodataId),
    });
    if (!biodata) {
      return res.status(404).json({ message: "Referenced biodata not found" });
    }

    const existing = await ContactRequestsCollection.findOne({
      biodataId: String(biodataId),
      requesterUid: uid,
      status: { $in: ["pending", "approved"] },
    });

    if (existing) {
      return res
        .status(409)
        .json({ message: "A pending or approved request already exists for this biodata" });
    }

    const doc = {
      biodataId: String(biodataId),
      biodataName: biodata.name || null,
      requesterEmail,
      requesterUid: uid,
      amount: amountNumber,
      currency: currency || "USD",
      paymentProvider: paymentProvider || "stripe",
      paymentMethod: paymentMethod || "card",
      cardLast4: last4Digits,
      status,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await ContactRequestsCollection.insertOne(doc);

    res.status(201).json({
      success: true,
      requestId: result.insertedId,
      message: "Contact request submitted successfully",
    });
  } catch (err) {
    console.error("Error creating contact request:", err);
    res.status(500).json({ message: "Failed to submit contact request" });
  }
});

app.get("/contact-requests", verifyToken, async (req, res) => {
  try {
    const { requesterUid, status } = req.query ?? {};
    const isAdmin = req.user?.role === "admin";

    let targetUid = req.user?.uid;
    if (isAdmin && requesterUid) {
      targetUid = requesterUid;
    } else if (requesterUid && requesterUid !== req.user?.uid) {
      return res
        .status(403)
        .json({ message: "You can only view your own contact requests" });
    }

    const filter = { requesterUid: targetUid };
    if (status) filter.status = status;

    const requests = await ContactRequestsCollection.find(filter)
      .sort({ createdAt: -1 })
      .toArray();

    const biodataIds = [
      ...new Set(requests.map((item) => String(item.biodataId))),
    ];

    const biodataDocs = await BiodataCollection.find(
      { biodataId: { $in: biodataIds } },
      {
        projection: {
          biodataId: 1,
          name: 1,
          contactEmail: 1,
          mobileNumber: 1,
        },
      }
    ).toArray();

    const biodataMap = new Map(
      biodataDocs.map((doc) => [String(doc.biodataId), doc])
    );

    const payload = requests.map((item) => {
      const biodata = biodataMap.get(String(item.biodataId));
      const isApproved = item.status === "approved";
      return {
        id: item._id?.toString(),
        biodataId: item.biodataId,
        requesterUid: item.requesterUid,
        requesterEmail: item.requesterEmail,
        status: item.status,
        amount: item.amount,
        currency: item.currency,
        paymentProvider: item.paymentProvider,
        paymentMethod: item.paymentMethod,
        cardLast4: item.cardLast4,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt,
        name: item.biodataName || biodata?.name || null,
        contactEmail: isApproved ? biodata?.contactEmail || null : null,
        mobileNumber: isApproved ? biodata?.mobileNumber || null : null,
      };
    });

    res.json(payload);
  } catch (err) {
    console.error("Error fetching contact requests:", err);
    res.status(500).json({ message: "Failed to fetch contact requests" });
  }
});

app.delete(
  "/contact-requests/:id",
  verifyToken,
  async (req, res) => {
    const { id } = req.params;
    let objectId;

    try {
      objectId = new ObjectId(id);
    } catch {
      return res.status(400).json({ message: "Invalid request id" });
    }

    const requestDoc = await ContactRequestsCollection.findOne({
      _id: objectId,
    });
    if (!requestDoc) {
      return res.status(404).json({ message: "Contact request not found" });
    }

    if (!ensureOwnerOrAdmin(req, res, requestDoc.requesterUid)) return;

    await ContactRequestsCollection.deleteOne({ _id: objectId });
    res.json({ success: true, message: "Contact request removed" });
  }
);

// ==================== LOCAL VS VERCEL ====================
if (process.env.NODE_ENV !== "production") {
  app.listen(port, () =>
    console.log(`🚀 Porinity Server running on port ${port}`)
  );
}

module.exports = app;