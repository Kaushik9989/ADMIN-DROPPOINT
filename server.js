// New cleaned version of server.js with only admin routes
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const path = require("path");
const MongoStore = require("connect-mongo");
const bodyParser = require("body-parser");
const flash = require("connect-flash");
const ejsMate = require("ejs-mate");
require("dotenv").config();

const User = require("./models/User/UserUpdated.js");
const Locker = require("./models/locker.js");

const app = express();
const PORT = 8080;
const MONGO_URI =process.env.MONGO_URI;
app.engine("ejs", ejsMate);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGO_URI,
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
  })
);

app.use(flash());
app.use((req, res, next) => {
  res.locals.messages = {
    success: req.flash("success"),
    error: req.flash("error"),
  };
  res.locals.admin = req.session.adminId || null;
  next();
});

function isAdmin(req, res, next) {
  if (req.session.adminId) return next();
  res.redirect("/admin/login");
}
app.get("/",(req,res)=>{
  res.render("adminLogin", {error :null});
})

app.get("/admin/login",(req,res)=>{
  res.render("adminLogin",{error : null});
})
// Admin Login Logic (basic auth)
app.post("/admin/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, role: "admin" });
  if (!user || !(await user.comparePassword(password))) {
    return res.render("adminLogin", { error: "Invalid credentials" });
  }
  req.session.adminId = user._id;
  res.redirect("/admin/dashboard");
});
app.get("/admin/dashboard", isAdmin, async (req, res) => {
  try {
    const user = await User.findOne({ role: "admin" });
    const lockers = await Locker.find({});
    res.render("adminDashboard", { lockers, user });
  } catch (err) {
    console.error("❌ Error loading admin dashboard:", err);
    req.flash("error", "Failed to load dashboard.");
    res.redirect("/admin/login");
  }
});

app.get("/admin/add-locker", isAdmin, (req, res) => {
  res.render("add-locker", {
    
  });
});
app.get("/admin/bookings", isAdmin, async (req, res) => {
  const user = await User.findById(req.session.adminId);
  try {
    const lockers = await Locker.find({});
    const bookings = [];

    for (const locker of lockers) {
      for (const compartment of locker.compartments) {
        if (compartment.isBooked || compartment.bookingInfo.userId) {
          const user = await User.findById(
            compartment.bookingInfo.userId
          ).select("username");

          bookings.push({
            lockerId: locker.lockerId,
            compartmentId: compartment.compartmentId,
            username: user ? user.username : "Unknown",
            otp: compartment.bookingInfo.otp,
            bookingTime: compartment.bookingInfo.bookingTime,
            isLocked: compartment.isLocked,
          });
        }
      }
    }

    res.render("admin-bookings", { user, bookings });
  } catch (err) {
    res.status(500).send("Error fetching bookings");
  }
});

app.get("/admin/add-locker", isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.session.adminId);
    res.render("add-locker", { user: user || { username: "Admin" } }); // ✅ FIXED path
  } catch (err) {
    console.error("Error rendering add-locker:", err);
    res.status(500).send("Internal server error");
  }
});

app.get("/admin/locker/:lockerId", isAdmin, async (req, res) => {
  try {
    const locker = await Locker.findOne({ lockerId: req.params.lockerId });
    if (!locker) return res.status(404).send("Locker not found");

    const user = await User.findById(req.session.adminId); // optional, if you need user info
    res.render("locker-details", { locker, user }); // Render the locker details view
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

app.post("/admin/add-locker", isAdmin, async (req, res) => {
  const { lockerId, address, lat, lng } = req.body;
  const compartments = req.body.compartments || {};

  // ✅ Check if lockerId already exists
  const existingLocker = await Locker.findOne({ lockerId });
  if (existingLocker) {
    req.flash("error", "Locker with this ID already exists.");
    return res.redirect("/admin/add-locker");
  }

  const compartmentArray = Object.values(compartments).map((c, i) => ({
    compartmentId: c.compartmentId || `C${i + 1}`,
    size: c.size || "medium",
    isBooked: false,
    isLocked: true,
    bookingInfo: {
      userId: null,
      bookingTime: null,
      otp: null,
    },
    qrCode: null,
  }));

  const newLocker = new Locker({
    lockerId,
    location: { lat, lng, address },
    compartments: compartmentArray,
  });

  await newLocker.save();
  req.flash("success", "Locker added successfully!");
  res.redirect("/admin/dashboard");
});


app.post("/admin/delete-locker", async (req, res) => {
  const { lockerId } = req.body;
  try {
    await Locker.findOneAndDelete({ lockerId });
    res.redirect("/admin/dashboard");
  } catch (err) {
    res.status(500).send("Error deleting locker");
  }
});

app.post("/admin/cancel", isAdmin, async (req, res) => {
  const { lockerId, compartmentId } = req.body;
  try {
    const locker = await Locker.findOne({ lockerId });
    const compartment = locker.compartments.find(
      (c) => c.compartmentId === compartmentId
    );
    if (compartment && compartment.isBooked) {
      compartment.isBooked = false;
      compartment.isLocked = true;
      compartment.qrCode = null;
      compartment.bookingInfo = {
        userId: null,
        otp: null,
        bookingTime: null,
      };
      await locker.save();
    }
    res.redirect("/admin/bookings");
  } catch (err) {
    res.status(500).send("Error cancelling booking");
  }
});


// Admin Logout
app.get("/admin/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/admin/login");
});

app.listen(PORT, () => {
  console.log(`🚀 Admin server running on http://localhost:${PORT}`);
});