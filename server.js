// New cleaned version of server.js with only admin routes
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const path = require("path");
const MongoStore = require("connect-mongo");
const bodyParser = require("body-parser");
const Terminal = require("./models/terminal.js"); 
const flash = require("connect-flash");
const ejsMate = require("ejs-mate");
require("dotenv").config();
const Merchant = require("./models/Merchant.js");
const User = require("./models/User/UserUpdated.js");
const Locker = require("./models/locker.js");
const Parcel = require("./models/ParcelUpdated.js");
const app = express();
const cron = require("node-cron");
const PORT = 8080;
const { setIo } = require('./lib/broadcaster');
const MONGO_URI =process.env.MONGO_URI;
app.engine("ejs", ejsMate);
const http = require('http');
const server = http.createServer(app);
const io = require('socket.io')(server, { cors: { origin: '*' } });

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

mongoose
  .connect(MONGO_URI)
  .then(() => {console.log("✅ MongoDB connected");startAdminWatchdog();})
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
  return res.redirect("/admin/login");
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
  if (!user) {
    return res.render("adminLogin", { error: "Admin not found" });
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
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

app.post('/api/terminal/heartbeat', async (req, res) => {
  try {
    const { lockerId, meta } = req.body;
    if (!lockerId) return res.status(400).json({ error: 'lockerId required' });

    const ip = req.ip || req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const now = new Date();

    const update = {
      lastSeen: now,
      status: 'online',
      ip,
      meta: meta || {},
      updatedAt: now
    };

    const locker = await Locker.findOneAndUpdate(
      { lockerId },
      { $set: update, $setOnInsert: { lockerId } },
      { upsert: true, new: true }
    );

    return res.json({ ok: true, lockerId: locker.lockerId, status: locker.status, lastSeen: locker.lastSeen });
  } catch (err) {
    console.error('heartbeat error', err);
    return res.status(500).json({ error: 'internal' });
  }
});








app.get('/admin/lockers', async (req, res) => {
  const lockers = await Locker.find().sort({ status: 1, lastSeen: 1 }).lean();
  res.render("lockersHealth", { lockers });
});


const bcrypt = require("bcrypt");

app.get("/create-admin", async (req, res) => {
  try {
    const adminExists = await User.findOne({ username: "admin" });
    if (adminExists) return res.send("Admin already exists");

    const admin = new User({
      username: "admin",
      password: "admin123",  // will get hashed
      role: "admin"
    });

    await admin.save();  // triggers pre-save hashing
    res.send("✅ Admin created with hashed password");
  } catch (err) {
    console.error("Error creating admin:", err);
    res.status(500).send("Failed");
  }
});


app.get("/admin/bookings", isAdmin, async (req, res) => {
  try {
    const admin = await User.findById(req.session.adminId);

    const parcels = await Parcel.find({
    }).sort({ createdAt: -1 }); // optional: newest first

    const bookings = parcels.map(parcel => ({
      parcelId: parcel._id,
      lockerId: parcel.lockerId || "N/A",
      compartmentId: parseInt(parcel.compartmentId) + 1 || "N/A",
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

app.get("/merchantValidate", isAdmin, async (req, res) => {
  try {
    const merchants = await Merchant.find().sort({ createdAt: -1 }).lean();
    res.render("validateMerchant", { merchants });
  } catch (err) {
    console.error("Merchant fetch error:", err);
    res.status(500).send("Server error fetching merchants.");
  }
});

app.post("/merchantValidate/:id", isAdmin, async (req, res) => {
  try {
    const merchantId = req.params.id;
    const merchant = await Merchant.findById(merchantId);
    if (!merchant) {
      return res.status(404).send("Merchant not found");
    }
    merchant.isValid = true;
    await merchant.save();
    console.log(merchantId);
    res.redirect("/merchantValidate");
  } catch (err) {
    console.error("Merchant validation error:", err);
    res.status(500).send("Error validating merchant.");
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
    compartmentId: c.compartmentId || `${i}`,
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



const UserAction = require('./models/userAction.js');

app.post("/analytics/user-action", async (req, res) => {
  const { step, method, path } = req.body;
  try{
  await UserAction.create({
    step,
    method,
    path,
    sessionId: req.sessionID,
    userId: req.session?.user?._id || null
  });
} catch(err){
  console.log(err);
}
  res.sendStatus(200);
});
app.get("/action_funnel", async (req, res) => {
   const user = await User.findById(req.session.adminId);
  const now = new Date();

  const todayStart = new Date(now.setHours(0, 0, 0, 0));
  const todayEnd = new Date(todayStart);
  todayEnd.setDate(todayEnd.getDate() + 1);

  const yesterdayStart = new Date(todayStart);
  yesterdayStart.setDate(yesterdayStart.getDate() - 1);
  const yesterdayEnd = new Date(todayStart);

  const [todayRaw, yesterdayRaw] = await Promise.all([
    UserAction.aggregate([
      { $match: { timestamp: { $gte: todayStart, $lt: todayEnd } } },
      { $group: { _id: "$step", count: { $sum: 1 } } }
    ]),
    UserAction.aggregate([
      { $match: { timestamp: { $gte: yesterdayStart, $lt: yesterdayEnd } } },
      { $group: { _id: "$step", count: { $sum: 1 } } }
    ])
  ]);

  const combineSteps = (raw) => {
    const result = {
      not_logged_in: 0,
      logged_in: 0,
      dashboard: 0,
      send_step_2: 0,
      payment_stage: 0,
      payment_completed: 0,
      parcel_booked: 0,
      abandoned_login: 0
    };

    let loginPage = 0;
    let loginTotal = 0;

    raw.forEach(({ _id, count }) => {
      if (_id === "login_page") {
        result.not_logged_in += count;
        loginPage = count;
      } else if (_id === "login_google" || _id === "login_phone") {
        result.logged_in += count;
        loginTotal += count;
      } else if (result[_id] !== undefined) {
        result[_id] = count;
      }
    });

    result.abandoned_login = Math.max(loginPage - loginTotal, 0);
    return result;
  };

  const todayData = combineSteps(todayRaw);
  const yesterdayData = combineSteps(yesterdayRaw);

  const steps = [
    "not_logged_in",
    "logged_in",
    "abandoned_login",
    "dashboard",
    "send_step_2",
    "payment_stage",
    "payment_completed",
    "parcel_booked"
  ];

  const funnel = steps.map(step => ({
    step,
    today: todayData[step] || 0,
    yesterday: yesterdayData[step] || 0
  }));

  res.render("funnelAction", { funnel,user });
});



app.get("/users", async (req, res) => {
  const user = await User.findById(req.session.adminId);
  try {
    const users = await User.find().sort({ createdAt: -1 }).lean();

    res.render("users", {
      users,user,
      activePage: "users"
    });
  } catch (err) {
    console.error("Failed to load users:", err);
    res.status(500).send("Error loading users");
  }
});
app.post("/admin/users/:id/delete", async (req, res) => {
  

  try {
    await User.findByIdAndDelete(req.params.id);
    res.redirect("/users");
  } catch (err) {
    console.error("Delete failed:", err);
    res.status(500).send("Failed to delete user");
  }
});













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


//// WATCHDOG

const WATCHDOG_SCHEDULE = '*/9 * * * * *';

const STALE_MS = 30 * 1000;
const twilio = require("twilio");
const client1 = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);




// assume Terminal, client1 (twilio), and emitTerminalStatusChange are imported

function startAdminWatchdog() {
  cron.schedule(WATCHDOG_SCHEDULE, async () => {
    const cutoff = new Date(Date.now() - STALE_MS);

    try {
      // filter used both for update and to fetch affected docs
      const staleFilter = {
        'status.online': true,
        $or: [
          { lastSeen: { $lt: cutoff } },
          { lastSeen: { $exists: false } }
        ]
      };

      // 1) mark stale terminals offline
      const updateRes = await Terminal.updateMany(staleFilter, {
        $set: {
          'status.online': false,
          'status.updatedBy': 'admin-watchdog',
          'status.offlineAt': new Date()
        }
      });

      // 2) fetch the affected docs (we need them to emit + notify)
      const affected = await Terminal.find(staleFilter).lean();

      // emit status change (offline) for each affected terminal
      for (const doc of affected) {
        try {
          await emitTerminalStatusChange({
            terminalId: doc.terminalId,
            isOnline: false,
            lastSeen: doc.lastSeen,
            status: doc.status
          });
        } catch (err) {
          console.error('[admin-watchdog] emit (offline) error for', doc.terminalId, err);
        }
      }

      // 3) send WhatsApp notifications for affected terminals that haven't been notified
      // Prefer storing notified under status.notified (boolean)
      for (const doc of affected) {
        try {
         

          await client1.messages.create({
            to: "whatsapp:+916281672715", // replace with real recipient logic
            from: "whatsapp:+15558076515",
            contentSid: "HX32104215669b7ff8c36acf31444ee9b2",
            contentVariables: JSON.stringify({
              1: doc.terminalId,
              2: "Offline",
              3: doc.lastSeen  ? new Date(new Date(doc.lastSeen).getTime() + 5.5 * 60 * 60 * 1000).toISOString().replace('Z', '+05:30') : "N/A"
            }),
          });

          console.log('[admin-watchdog] WhatsApp sent for', doc.terminalId);

          // persist notified flag under status.notified so next run skips it
          await Terminal.updateOne(
            { _id: doc._id },
            { $set: { 'status.notified': true, 'status.notifiedAt': new Date() } }
          ).catch(err => {
            console.error('[admin-watchdog] failed to persist notified flag for', doc.terminalId, err);
          });

        } catch (err) {
          console.error('[admin-watchdog] WhatsApp error for', doc.terminalId, err);
          // optional: record notify failure timestamp or increment a counter
          await Terminal.updateOne(
            { _id: doc._id },
            { $set: { 'status.notifyErrorAt': new Date() } }
          ).catch(() => {});
        }
      }

      // 4) Defensive: flip terminals back online if they've reported recently
      const liveCutoff = new Date(Date.now() - STALE_MS / 2);
      const reactivateFilter = {
        lastSeen: { $gte: liveCutoff },
        'status.online': false
      };

      // fetch docs to reactivate so we can emit events for them
      const toReactivate = await Terminal.find(reactivateFilter).lean();

      if (toReactivate.length) {
        const reactRes = await Terminal.updateMany(reactivateFilter, {
          $set: {
            'status.online': true,
            'status.updatedBy': 'admin-watchdog',
            'status.offlineAt': null,
            'status.notified': false // clear notified so future outages can notify again
          }
        });

        // emit status change for each reactivated terminal
        for (const doc of toReactivate) {
           await client1.messages.create({
            to: "whatsapp:+916281672715", // replace with real recipient logic
            from: "whatsapp:+15558076515",
            contentSid: "HXa98f3ff30c1e477467503e9ef4ea5e86",
            contentVariables: JSON.stringify({
              1: doc.terminalId,
              2: doc.lastSeen  ? new Date(new Date(doc.lastSeen).getTime() + 5.5 * 60 * 60 * 1000).toISOString().replace('Z', '+05:30') : "N/A"
            }),
          });
          try {
            await emitTerminalStatusChange({
              terminalId: doc.terminalId,
              isOnline: true,
              lastSeen: doc.lastSeen,
              status: doc.status
            });
          } catch (err) {
            console.error('[admin-watchdog] emit (reactivated) error for', doc.terminalId, err);
          }
        }

        console.log('[admin-watchdog] reactivated:', reactRes.modifiedCount || reactRes.nModified || toReactivate.length);
      }

      // 5) Summary logging
      console.log(`[admin-watchdog] flipped offline: ${updateRes.modifiedCount || updateRes.nModified || 0}, affected fetched: ${affected.length}, reactivated: ${toReactivate ? toReactivate.length : 0}`);

    } catch (err) {
      console.error('[admin-watchdog] error during run', err);
    }
  }, {
    scheduled: true,
    timezone: 'UTC'
  });

  console.log('[admin-watchdog] started — checking according to schedule');
}

module.exports = { startAdminWatchdog };


io.on('connection', socket => {
  console.log('[socket] client connected', socket.id);
  socket.on('disconnect', () => console.log('[socket] client disconnected', socket.id));
});

// admin/admin-watchdog.js

function emitTerminalStatusChange(payload) {
  // payload: { terminalId, isOnline, lastSeen, status }
  io.emit('terminal:status', payload);
}






// server.js (or wherever your route lives)
app.get('/terminals', async (req, res) => {
  try {
    const docs = await Terminal.find({}).sort({ terminalId: 1 }).lean();
    const now = Date.now();
    const thresholdMs = (process.env.HEARTBEAT_THRESHOLD_MS && Number(process.env.HEARTBEAT_THRESHOLD_MS)) || 30 * 1000;

    const withOnline = docs.map(d => {
      const lastSeenTs = d && d.lastSeen ? new Date(d.lastSeen).getTime() : null;
      const isOnline = lastSeenTs && (now - lastSeenTs <= thresholdMs);
      // helper to format IST on server for first-render
      const fmtIST = (dt) => {
        if (!dt) return '—';
        try {
          return new Date(dt).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
        } catch (e) {
          return new Date(dt).toISOString();
        }
      };

      // small health shortcuts for template
      const health = (d.status && d.status.health) || {};
      const batteryPercent = health.battery && typeof health.battery.percent === 'number' ? health.battery.percent : null;
      const cpuLoad = health.cpu && typeof health.cpu.loadPercent === 'number' ? health.cpu.loadPercent : null;
      const memUsed = health.memory && typeof health.memory.usedBytes === 'number' ? health.memory.usedBytes : null;
      const memTotal = health.memory && typeof health.memory.totalBytes === 'number' ? health.memory.totalBytes : null;
      const memStr = (memUsed && memTotal) ? `${Math.round(memUsed/1024/1024)}MB / ${Math.round(memTotal/1024/1024)}MB` : '—';
      const diskSummary = (health.disk && health.disk.length) ? health.disk.map(dk => `${Math.round((dk.used||0)/1024/1024)}MB`).join(', ') : '—';
      const wifiSsid = health.wifi && health.wifi.ssid ? health.wifi.ssid : '—';
      const uptime = typeof health.uptimeSeconds === 'number' ? `${Math.floor(health.uptimeSeconds/3600)}h ${Math.floor((health.uptimeSeconds%3600)/60)}m` : '—';

      return {
        ...d,
        isOnline,
        lastSeenIST: d.lastSeen ? fmtIST(d.lastSeen) : '—',
        localTimeIST: (d.status && d.status.localTime) ? fmtIST(d.status.localTime) : '—',
        _healthShort: {
          batteryPercent,
          cpuLoad,
          memStr,
          diskSummary,
          wifiSsid,
          uptime
        }
      };
    });

    res.render('terminals', { terminals: withOnline });
  } catch (err) {
    console.error('/terminals render error', err);
    res.status(500).send('server error');
  }
});















app.get('/terminals/add', (req, res) => {
  res.render('add-terminal');
});




app.post('/terminals/add', async (req, res) => {
  try {
    const { terminalId } = req.body;
    if (!terminalId || terminalId.trim() === '') {
      return res.render('add-terminal', { 
        message: "Terminal ID is required.",
        messageType: "error"
      });
    }

    // Create new terminal doc
    await Terminal.create({
      terminalId: terminalId.trim(),
      lastSeen: null,
      status: {
        online: false,
        updatedBy: "manual-create"
      }
    });

    return res.render('add-terminal', {
      message: "Terminal added successfully!",
      messageType: "success"
    });

  } catch (err) {
    console.error(err);

    let msg = "Something went wrong.";
    if (err.code === 11000) {
      msg = "Terminal ID already exists.";
    }

    res.render('add-terminal', { 
      message: msg,
      messageType: "error"
    });
  }
});

// Admin Logout
app.get("/admin/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/admin/login");
});


///// analytics for every locker

app.get("/analytics/lockers", async (req, res) => {
  const lockers = await Locker.find().select("lockerId stats location.address");
  res.render("admin-locker-analytics", { lockers });
});




//////// API CREATION

const crypto = require("crypto");
const Partner = require("./models/partnerSchema.js");
const PartnerRequest = require("./models/partnerRequest");


function generateApiKey(partnerName) {
  const safeName = partnerName.toLowerCase().replace(/[^a-z0-9]/g, "");
  const random = crypto.randomBytes(24).toString("hex");
  return `dp_live_${safeName}_${random}`;
}




app.get("/admin/create-partner", async (req, res) => {
  try {
    const requests = await PartnerRequest.find().sort({ createdAt: -1 });

    res.render("admin_create_partner", {
      requests
    });
  } catch (e) {
    console.error(e);
    res.send("Internal error");
  }
});

app.post("/admin/partner-requests/:id/approve", async (req, res) => {
  try {
    const request = await PartnerRequest.findById(req.params.id);
    if (!request) return res.redirect("/admin/create-partner");

    // Prevent double approval
    if (request.status !== "pending") {
      return res.redirect("/admin/create-partner");
    }

    // Check if partner already exists
    const existing = await Partner.findOne({ email: request.email });

    if (!existing) {
      const apiKey = generateApiKey(request.companyName);

      await Partner.create({
        name: request.contactName,
        email: request.email,
        phone: request.phone,
        companyName: request.companyName,
        apiKey,
        isApproved: true,
      });
    }

    request.status = "approved";
    await request.save();

    res.redirect("/admin/create-partner");
  } catch (e) {
    console.error("APPROVE ERROR:", e);
    res.redirect("/admin/create-partner");
  }
});



app.post("/admin/partner-requests/:id/reject", async (req, res) => {
  try {
    await PartnerRequest.findByIdAndUpdate(req.params.id, {
      status: "rejected",
    });
  } catch (e) {
    console.error("REJECT ERROR:", e);
  }

  res.redirect("/admin/create-partner");
});



  // List all partners for modal
app.get("/admin/api/partners", async (req, res) => {
  try {
    const partners = await Partner.find().sort({ createdAt: -1 }).lean();
    res.json({ success: true, partners });
  } catch (e) {
    res.status(500).json({ success: false });
  }
});


//// CUSTOMER AGENT ONBOARD

const CustomerAgent = require("./models/customerAgent");
const AgentAccessRequest = require("./models/agentAccessRequest.js");
// Show onboarding form
app.get("/admin/agents/new", async (req, res) => {
  try {
    const agents = await CustomerAgent.find({ isActive: true }).sort({ createdAt: -1 });
    const requests = await AgentAccessRequest.find({ status: "pending" }).sort({ createdAt: -1 });

    res.render("agent_new", {
      agents,
      requests,   // 👈 add this
      error: null,
      success: null
    });
  } catch (err) {
    console.error("Error fetching agents/requests:", err);
    res.status(500).send("Internal Server Error");
  }
});

app.post("/admin/agent-requests/:id/approve", async (req, res) => {
  try {
    const request = await AgentAccessRequest.findById(req.params.id);
    if (!request || request.status !== "pending") {
      return res.redirect("/admin/agents/new");
    }

    // Check if agent already exists
    const existing = await CustomerAgent.findOne({ email: request.email });
    if (existing) {
      request.status = "approved";
      request.adminNote = "Agent already existed";
      await request.save();
      return res.redirect("/admin/agents/new");
    }

    // Generate Agent ID
    const count = await CustomerAgent.countDocuments();
    const agentId = "AGT-" + String(count + 1).padStart(4, "0");

    await CustomerAgent.create({
      agentId,
      name: request.name,
      email: request.email,
      phone: request.phone,
      role: "agent",
      isActive: true,
    });

    request.status = "approved";
    request.reviewedAt = new Date();
    request.reviewedBy = req.user?.email || "admin";
    await request.save();

    res.redirect("/admin/agents/new");
  } catch (err) {
    console.error("Approve request error:", err);
    res.redirect("/admin/agents/new");
  }
});

app.post("/admin/agent-requests/:id/reject", async (req, res) => {
  try {
    await AgentAccessRequest.findByIdAndUpdate(req.params.id, {
      status: "rejected",
      reviewedAt: new Date(),
      reviewedBy: req.user?.email || "admin",
    });

    res.redirect("/admin/agents/new");
  } catch (err) {
    console.error("Reject request error:", err);
    res.redirect("/admin/agents/new");
  }
});





// Create agent
app.post("/admin/agents", async (req, res) => {
  try {
    const { name, email, phone, role } = req.body;

    if (!name || !email) {
      return res.render("agent_new", {
        error: "Name and email are required",
        success: null,
      });
    }

    // Check if already exists
    const existing = await CustomerAgent.findOne({ email });
    if (existing) {
      return res.render("agent_new", {
        error: "Agent with this email already exists",
        success: null,
      });
    }

    // Generate Agent ID: AGT-0001
    const count = await CustomerAgent.countDocuments();
    const agentId = "AGT-" + String(count + 1).padStart(4, "0");

    const agent = await CustomerAgent.create({
      agentId,
      name,
      email,
      phone,
      role: role || "agent",
      isActive: true,
    });
 const agents = await CustomerAgent.find({ isActive: true }).sort({ createdAt: -1 });
    const requests = await AgentAccessRequest.find({ status: "pending" }).sort({ createdAt: -1 });


    res.render("agent_new", {
       agents,
      requests, 
      error: null,
      success: `Agent ${agent.name} created successfully with ID ${agent.agentId}`,
    });
  } catch (err) {
    console.error("Create agent error:", err);
    res.render("agent_new", {
      error: "Something went wrong while creating agent",
      success: null,
    });
  }
});

app.get("/admin/customer/analytics", async (req, res) => {
    try {
        const agents = await CustomerAgent.find({ isActive: true });

        // Aggregate Global Stats
        const globalStats = agents.reduce((acc, agent) => {
            acc.totalResolved += agent.stats.ticketsResolved;
            acc.totalSlaBreaches += agent.stats.slaBreaches;
            acc.totalActive += agent.activeTickets;
            return acc;
        }, { totalResolved: 0, totalSlaBreaches: 0, totalActive: 0 });

        // Calculate Average Resolution Time (Global)
        const totalAgentsWithStats = agents.filter(a => a.stats.ticketsResolved > 0).length;
        const avgResTime = agents.reduce((sum, a) => sum + a.stats.avgResolutionTimeSeconds, 0) / (agents.length || 1);

        res.render("customercare_analytics", {
            agents,
            globalStats,
            avgResTime: Math.round(avgResTime / 60), // Convert to minutes
            error: null
        });
    } catch (err) {
        console.error("Analytics Error:", err);
        res.status(500).send("Internal Server Error");
    }
});













app.listen(PORT, () => {
  console.log(`🚀 Admin server running on http://localhost:${PORT}`);
});