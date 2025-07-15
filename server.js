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
const Parcel = require("./models/ParcelUpdated.js");
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
  try {
    const admin = await User.findById(req.session.adminId);

    const parcels = await Parcel.find({
      status: { $in: ["awaiting_drop", "awaiting_pick"] }
    }).sort({ createdAt: -1 }); // optional: newest first

    const bookings = parcels.map(parcel => ({
      parcelId: parcel._id,
      lockerId: parcel.lockerId || "N/A",
      compartmentId: parcel.compartmentId || "N/A",
      status: parcel.status,
      otp: parcel.accessCode,
      senderName: parcel.senderName || "—",
      receiverName: parcel.receiverName || "—",
      receiverPhone: parcel.receiverPhone || "—",
      createdAt: parcel.createdAt,
      expiresAt: parcel.expiresAt,
      paymentOption: parcel.paymentOption,
      paymentStatus: parcel.paymentStatus,
    }));

    res.render("admin-bookings", { user: admin, bookings });
  } catch (err) {
    console.error("Error loading parcel bookings:", err);
    res.status(500).send("Internal server error");
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
const FunnelEvent = require("./models/funnelEvent.js");

async function trackFunnelStep(req, step, metadata = {}) {
  try {
    const ua = uaParser(req.headers['user-agent']);
    const device = ua.device.type || 'desktop';

    await FunnelEvent.create({
      sessionId: req.sessionID,
      userId: req.user?._id || null,
      phone: req.body?.phone || null,
      step,
      metadata: {
        ...metadata,
        device
      }
    });
  } catch (err) {
    console.error("Funnel tracking error:", err);
  }
}
async function getAverageDurations() {
  const sessions = await FunnelEvent.aggregate([
    {
      $match: {
        step: { $in: [
          "visit_landing_page",
          "login_phone",
          "otp_entered",
          "dashboard_loaded",
          "send_parcel_clicked",
          "send_parcel_submitted",
          "parcel_created",
          "parcel_picked"
        ]}
      }
    },
    {
      $group: {
        _id: "$sessionId",
        steps: {
          $push: {
            step: "$step",
            timestamp: "$timestamp"
          }
        }
      }
    }
  ]);

  const durations = {
    loginToDashboard: [],
    sendStartToSubmit: [],
    parcelCreateToPickup: []
  };

  for (const session of sessions) {
    const stepMap = {};
    session.steps.forEach(e => stepMap[e.step] = new Date(e.timestamp));

    // Login → Dashboard
    if (stepMap["login_phone"] && stepMap["dashboard_loaded"]) {
      const delta = stepMap["dashboard_loaded"] - stepMap["login_phone"];
      if (delta >= 0 && delta <= 600000) durations.loginToDashboard.push(delta);
    }

    // Send Start → Submit
    if (stepMap["send_parcel_clicked"] && stepMap["send_parcel_submitted"]) {
      const delta = stepMap["send_parcel_submitted"] - stepMap["send_parcel_clicked"];
      if (delta >= 0 && delta <= 600000) durations.sendStartToSubmit.push(delta);
    }

    // Parcel Created → Pickup
    if (stepMap["parcel_created"] && stepMap["parcel_picked"]) {
      const delta = stepMap["parcel_picked"] - stepMap["parcel_created"];
      if (delta >= 0 && delta <= 24 * 60 * 60 * 1000) // < 24h
        durations.parcelCreateToPickup.push(delta);
    }
  }

  // Helper to compute avg
  const avg = arr =>
    arr.length ? (arr.reduce((a, b) => a + b, 0) / arr.length / 1000).toFixed(2) : "0.00";

  return {
    avgLoginToDashboard: avg(durations.loginToDashboard),
    avgSendFlow: avg(durations.sendStartToSubmit),
    avgPickupTime: avg(durations.parcelCreateToPickup)
  };
}



app.get("/admin/analytics",async(req,res)=>{
    
  try {
    const user = await User.findOne({ role: "admin" });
    console.log("✅ /admin/funnel route hit");

    const timingData = await getAverageDurations();
    console.log("✅ Timing data calculated");

    const loginPhoneCount = await FunnelEvent.distinct("sessionId", { step: "login_phone" }).then(d => d.length);
    const loginOAuthCount = await FunnelEvent.distinct("sessionId", { step: "login_oauth" }).then(d => d.length);
    const totalVisits = await FunnelEvent.distinct("sessionId", { step: "visit_landing_page" }).then(d => d.length);
    const loginPhone = await FunnelEvent.distinct("sessionId", { step: "login_phone" }).then(d => d.length);
    const otpEntered = await FunnelEvent.distinct("sessionId", { step: "otp_entered" }).then(d => d.length);
    const dashboard = await FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" }).then(d => d.length);

    const drop1 = totalVisits - loginPhone;
    const drop2 = loginPhone - otpEntered;
    const drop3 = Math.max(otpEntered - dashboard, 0);
    const successRate = totalVisits > 0 ? ((dashboard / totalVisits) * 100).toFixed(2) : "0.00";
    const successRateNum = Math.min(parseFloat(successRate), 100);
    const abandonmentRate = (100 - successRateNum).toFixed(2);

    const [visitSessions, loginSessions, otpSessions, dashboardSessions] = await Promise.all([
      FunnelEvent.distinct("sessionId", { step: "visit_landing_page" }),
      FunnelEvent.distinct("sessionId", { step: { $in: ["login_phone", "login_oauth"] } }),
      FunnelEvent.distinct("sessionId", { step: "otp_entered" }),
      FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" })
    ]);

    const loginCount = loginSessions.length;
    const otpCount = otpSessions.length;
    const dashboardCount = dashboardSessions.length;

    const dropAfterVisit = totalVisits - loginCount;
    const dropAfterLogin = loginCount - otpCount;
    const dropAfterOTP = Math.max(otpCount - dashboardCount, 0);

    const dashboardSession = await FunnelEvent.distinct("sessionId", { step: "dashboard_loaded" });
    const sendParcelSessions = await FunnelEvent.distinct("sessionId", { step: "send_parcel_clicked" });

    const sentCount = sendParcelSessions.length;
    const dashboardOnly = dashboardSession.filter(id => !sendParcelSessions.includes(id));
    const notSentCount = dashboardOnly.length;

    const stuckStats = {
      at_visit_page: dropAfterVisit,
      at_login: dropAfterLogin,
      at_otp: dropAfterOTP
    };

    console.log("✅ All data fetched, rendering page");

    res.render("funnelDashboard", {
      totalVisits,
      loginCount,
      otpCount,
      dashboardCount,
      successRate,
      abandonmentRate,
      stuckStats,
      timingData,
      loginPhone,
      otpEntered,
      dashboard,
      drop1,
      drop2,
      drop3,
      loginPhoneCount,
      sentCount,
      notSentCount,
      loginOAuthCount,
      user
    });

  } catch (err) {
    console.error("❌ Error in /admin/funnel:", err);
    res.status(500).send("Something broke while loading the funnel dashboard.");
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