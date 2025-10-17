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
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://your-client-app.web.app",
    ],
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
let isDBInitialized = false;

async function initDB() {
  if (!isDBInitialized) {
    await client.connect();
    const db = client.db("PorinityDB");

    BiodataCollection = db.collection("BiodataCollection");
    UsersCollection = db.collection("Users");
    ContactRequestsCollection = db.collection("ContactRequests");

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
const sanitizeBiodata = (doc = {}) => {
  const { _id, numericBiodataId, ...rest } = doc;
  return rest;
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

const ensureOwnerOrAdmin = (req, res, uid) => {
  if (req.user?.role === "admin") return true;
  if (req.user?.uid && req.user.uid === uid) return true;
  res.status(403).json({ message: "Forbidden" });
  return false;
};

const getNextBiodataNumericId = async () => {
  const total = await BiodataCollection.countDocuments();
  return total + 1;
};

// ==================== AUTH (JWT) ====================
app.post("/jwt", async (req, res) => {
  const { email } = req.body;
  const userInfo = await UsersCollection.findOne({ email });
  const uid = userInfo?.uid || "";
  const userType = userInfo?.userType || "basic";
  const role = userInfo?.role || "user";

  const payload = { email, uid, userType, role };
  const isProd = process.env.NODE_ENV === "production";

  const accessToken = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
  const refreshToken = jwt.sign(payload, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: "7d",
  });

  res
    .cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: "strict",
      path: "/",
    })
    .cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? "none" : "strict",
      path: "/",
    })
    .send({ success: true });
});

app.post("/refresh", (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  const isProd = process.env.NODE_ENV === "production";

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
        secure: isProd,
        sameSite: "strict",
      })
      .send({ success: true });
  });
});

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
    req.user = decoded;
    next();
  });
};

// ==================== PUBLIC ROUTES ====================
app.get("/", (req, res) => {
  res.send("🚀Porinity server is running...");
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
      data: records.map(sanitizeBiodata),
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

app.get("/biodata/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const doc = await BiodataCollection.findOne({ biodataId: id });
    if (!doc) return res.status(404).json({ message: "Biodata not found" });
    res.json(doc);
  } catch (err) {
    console.error("Error fetching biodata by id:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ==================== USER ROUTES ====================
app.post("/register", async (req, res) => {
  const { email, uid, role, userType } = req.body;

  const existingUser = await UsersCollection.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = {
    email,
    uid,
    userType,
    role,
    createdAt: new Date(),
  };
  await UsersCollection.insertOne(newUser);

  res.status(201).json({
    success: true,
    user: { email, uid, userType, role },
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

// ==================== BIODATA MANAGEMENT ====================
app.get("/biodata/user/:uid", verifyToken, async (req, res) => {
  const { uid } = req.params;
  if (!ensureOwnerOrAdmin(req, res, uid)) return;

  const biodata = await BiodataCollection.findOne({ uid });
  if (!biodata) {
    return res.status(404).json({ message: "Biodata not found" });
  }

  res.json(sanitizeBiodata(biodata));
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

    await BiodataCollection.updateOne(
      { _id: biodata._id },
      {
        $set: {
          premiumStatus: "pending",
          premiumRequestedAt: new Date(),
          premiumReviewedAt: null,
          updatedAt: new Date(),
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