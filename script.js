/**
 * VoteX - Main Script
 * Handles state management, authentication, voting, and admin functionality.
 */

// ---------- State & Storage ----------
const ls = {
  get: (k, def = null) => {
    try {
      const v = localStorage.getItem(k);
      return v ? JSON.parse(v) : def;
    } catch {
      return def;
    }
  },
  set: (k, v) => localStorage.setItem(k, JSON.stringify(v)),
  rawGet: (k) => localStorage.getItem(k),
  rawSet: (k, v) => localStorage.setItem(k, v),
  del: (k) => localStorage.removeItem(k),
};

const defaultOptions = ["Option A", "Option B", "Option C"];
const defaults = {
  users: {},
  votes: {},
  options: [],
  userVotes: {}, // { username: "Option A" }
  settings: {
    votingOpen: true,
    showResultsToUsers: true,
    allowMultipleVotes: false,
    requireFaceCheck: true, // New setting
  },
  biometrics: {}, // { username: credentialId }
  faceEnrollments: {}, // { username: true }
  faceDescriptors: {}, // { username: Float32Array[] }
};

const state = {
  users: ls.get("va_users", ls.get("users", defaults.users)),
  votes: ls.get("va_votes", ls.get("votes", defaults.votes)),
  options: ls.get("va_options", defaults.options),
  userVotes: ls.get("va_userVotes", defaults.userVotes),
  settings: ls.get("va_settings", defaults.settings),
  user: ls.rawGet("va_userLoggedIn") || ls.rawGet("userLoggedIn"),
  admin: ls.rawGet("va_adminLoggedIn") === "true",
  biometrics: ls.get("va_biometrics", defaults.biometrics),
  faceEnrollments: ls.get("va_faceEnrollments", defaults.faceEnrollments),
  faceDescriptors: ls.get("va_faceDescriptors", defaults.faceDescriptors),
  sortByVotes: false,
  modelsLoaded: false,
};

// Rehydrate face descriptors into Float32Array
Object.keys(state.faceDescriptors).forEach(user => {
  state.faceDescriptors[user] = new Float32Array(Object.values(state.faceDescriptors[user]));
});

// Initialize options and votes
(function initOptionsVotes() {
  if (!state.options || !state.options.length) {
    const legacyOpts = Object.keys(state.votes || {});
    state.options = legacyOpts.length ? legacyOpts : defaultOptions.slice();
  }
  state.options.forEach((opt) => {
    if (typeof state.votes[opt] !== "number") state.votes[opt] = 0;
  });
  saveAll();
})();

// Theme
(function initTheme() {
  const saved = ls.rawGet("va_theme") || "light";
  document.documentElement.setAttribute("data-theme", saved);
})();

function saveAll() {
  ls.set("va_users", state.users);
  ls.set("va_votes", state.votes);
  ls.set("va_options", state.options);
  ls.set("va_userVotes", state.userVotes);
  ls.set("va_settings", state.settings);
  ls.set("va_biometrics", state.biometrics);
  ls.set("va_faceEnrollments", state.faceEnrollments);
  ls.set("va_faceDescriptors", state.faceDescriptors);
  // keep legacy votes in sync (optional)
  ls.set("votes", state.votes);
}

// ---------- Utils ----------
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

function toast(msg, type = "") {
  const el = document.createElement("div");
  el.className = "toast" + (type ? " " + type : "");
  el.textContent = msg;
  $("#toastWrap").appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function percent(count, total) {
  if (!total) return 0;
  return Math.round((count / total) * 100);
}

/**
 * Improved sanitization to prevent XSS.
 */
function sanitize(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function switchView(id) {
  $$(".view").forEach((v) => v.classList.remove("active"));
  $(id).classList.add("active");
}

function setTheme(t) {
  document.documentElement.setAttribute("data-theme", t);
  ls.rawSet("va_theme", t);
}

// ---------- Password helpers ----------
/**
 * Improved password strength calculation.
 */
function scorePassword(pw) {
  let score = 0;
  if (!pw) return score;

  // Length factor (0-40 points)
  score += Math.min(pw.length, 12) * 3.33;

  // Diversity factors (60 points)
  if (/[a-z]/.test(pw)) score += 15;
  if (/[A-Z]/.test(pw)) score += 15;
  if (/\d/.test(pw)) score += 15;
  if (/[^A-Za-z0-9]/.test(pw)) score += 15;

  return Math.min(100, Math.round(score));
}

// ---------- Auth ----------
let tempFaceDescriptor = null;

async function startRegistrationScan() {
  const err = $("#reg-scan-error");
  if (err) err.textContent = "";

  startFaceVerification(async (descriptor) => {
    if (!descriptor) return toast("Face scan failed. Try again.", "error");

    // Uniqueness check
    const threshold = 0.55;
    const isDuplicate = Object.values(state.faceDescriptors).some(stored => {
      const distance = faceapi.euclideanDistance(descriptor, stored);
      return distance < threshold;
    });

    if (isDuplicate) {
      if (err) err.textContent = "This face is already registered with another account.";
      toast("Identity already exists in VoteX.", "error");
      return;
    }

    tempFaceDescriptor = descriptor;
    $("#register-step-1").classList.add("hidden");
    $("#register-step-2").classList.remove("hidden");
    toast("Face scanned! Now choose your username.", "success");
  }, true); // pass 'true' to indicate we want the descriptor back
}

function register() {
  const user = $("#reg-username").value.trim();
  const pass = $("#reg-password").value;
  const err = $("#register-error");
  err.textContent = "";

  if (!tempFaceDescriptor) return (err.textContent = "Please scan your face first.");
  if (user.length < 3)
    return (err.textContent = "Username must be at least 3 characters.");
  if (pass.length < 6)
    return (err.textContent = "Password must be at least 6 characters.");
  if (!/^[A-Za-z0-9_]+$/.test(user))
    return (err.textContent = "Only letters, numbers, and underscore allowed.");
  if (state.users[user]) return (err.textContent = "Username already exists.");

  state.users[user] = pass;
  state.faceEnrollments[user] = true;
  state.faceDescriptors[user] = Array.from(tempFaceDescriptor); // stored as array
  saveAll();

  const enrollBio = $("#check-reg-bio-auto")?.checked;

  state.user = user;
  ls.rawSet("va_userLoggedIn", user);

  const runSetups = async () => {
    if (enrollBio) {
      toast("Linking Biometrics...", "info");
      await registerBiometrics();
    }
    renderVoteView();
    switchView("#view-vote");
    toast("Welcome to VoteX, " + user + "!", "success");
    tempFaceDescriptor = null;
  };
  runSetups();
}

function login() {
  const user = $("#login-username").value.trim();
  const pass = $("#login-password").value.trim();
  const err = $("#login-error");
  err.textContent = "";

  if (state.users[user] && state.users[user] === pass) {
    state.user = user;
    ls.rawSet("va_userLoggedIn", user);
    renderVoteView();
    switchView("#view-vote");
    toast(`Welcome, ${user}!`, "success");
  } else {
    err.textContent = "Invalid username or password.";
  }
}

function logoutUser() {
  ls.del("va_userLoggedIn");
  state.user = null;
  switchView("#view-login");
  toast("Logged out.");
}

function adminLogin() {
  const user = $("#admin-username").value.trim();
  const pass = $("#admin-password").value.trim();
  const err = $("#admin-error");
  err.textContent = "";

  if (user === "admin" && pass === "admin123") {
    state.admin = true;
    ls.rawSet("va_adminLoggedIn", "true");
    renderAdmin();
    switchView("#view-admin");
    toast("Admin logged in.", "success");
  } else {
    err.textContent = "Invalid admin credentials.";
  }
}

function logoutAdmin() {
  state.admin = false;
  ls.del("va_adminLoggedIn");
  switchView("#view-admin-login");
  toast("Admin logged out.");
}

// ---------- Biometric Authentication (WebAuthn Mock/Local) ----------
async function registerBiometrics() {
  if (!window.PublicKeyCredential) return toast("Biometrics not supported on this browser.", "error");
  if (!state.user) return;

  try {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const createOptions = {
      publicKey: {
        challenge,
        rp: { name: "VoteX" },
        user: {
          id: new TextEncoder().encode(state.user),
          name: state.user,
          displayName: state.user
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        authenticatorSelection: { authenticatorAttachment: "platform" },
        timeout: 60000
      }
    };

    const credential = await navigator.credentials.create(createOptions);
    if (credential) {
      state.biometrics[state.user] = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
      saveAll();
      toast("Biometrics registered successfully!", "success");
    }
  } catch (err) {
    console.error(err);
    toast("Failed to register biometrics: " + err.message, "error");
  }
}

async function loginWithBiometrics() {
  if (!window.PublicKeyCredential) return toast("Biometrics not supported.", "error");

  // For this demo, we'll try to find any registered user or ask for a username?
  // Let's simplify: find the last user who logged in or ask to type username first.
  const username = $("#login-username").value.trim();
  if (!username) return toast("Please enter your username first.", "warn");
  if (!state.biometrics[username]) return toast("No biometrics registered for this user.", "warn");

  try {
    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const getOptions = {
      publicKey: {
        challenge,
        allowCredentials: [{
          id: Uint8Array.from(atob(state.biometrics[username]), c => c.charCodeAt(0)),
          type: "public-key"
        }],
        timeout: 60000
      }
    };

    const assertion = await navigator.credentials.get(getOptions);
    if (assertion) {
      state.user = username;
      ls.rawSet("va_userLoggedIn", username);
      renderVoteView();
      switchView("#view-vote");
      toast(`Welcome back, ${username}! (Biometric Login)`, "success");
    }
  } catch (err) {
    console.error(err);
    toast("Biometric login failed.", "error");
  }
}

async function loginWithFace() {
  const username = $("#login-username").value.trim();
  if (!username) return toast("Please enter your username first.", "warn");
  if (!state.faceEnrollments[username]) return toast("Face login not enabled for this user.", "warn");

  startFaceVerification(() => {
    state.user = username;
    ls.rawSet("va_userLoggedIn", username);
    renderVoteView();
    switchView("#view-vote");
    toast(`Welcome back, ${username}! (Face Login)`, "success");
  });
}

// ---------- Face Recognition ----------
const FACE_MODELS_URL = "https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/"; // Using a reliable model URL

async function loadModels() {
  const status = $("#faceStatus");
  if (state.modelsLoaded) return;
  try {
    if (status) status.textContent = "Loading AI models...";
    const models = [
      faceapi.nets.tinyFaceDetector.loadFromUri(FACE_MODELS_URL),
      faceapi.nets.ssdMobilenetv1.loadFromUri(FACE_MODELS_URL),
      faceapi.nets.faceLandmark68Net.loadFromUri(FACE_MODELS_URL),
      faceapi.nets.faceRecognitionNet.loadFromUri(FACE_MODELS_URL),
    ];
    await Promise.all(models);
    state.modelsLoaded = true;
    console.log("Face models loaded successfully.");
  } catch (err) {
    console.error("Face-api models failed to load:", err);
    if (status) status.textContent = "Error loading AI models. Check connection.";
    throw err; // Re-throw to handle in caller
  }
}

let videoStream = null;
async function startFaceVerification(onSuccess, getDescriptor = false) {
  const modal = $("#faceModal");
  const video = $("#video");
  const status = $("#faceStatus");
  modal.classList.remove("hidden");
  await loadModels();

  try {
    if (status) status.textContent = "Initializing camera...";
    videoStream = await navigator.mediaDevices.getUserMedia({
      video: { width: 320, height: 240, facingMode: "user" }
    });
    video.srcObject = videoStream;

    // Explicitly play and wait
    try {
      await video.play();
    } catch (e) {
      console.warn("Autoplay was blocked, user gesture might be needed", e);
    }

    if (status) status.textContent = "Scanning face... Focus!";

    let verified = false;
    const checkFace = async () => {
      if (!videoStream || verified) return;

      try {
        // Switch back to TinyFaceDetector for much better real-time performance
        const options = new faceapi.TinyFaceDetectorOptions({ inputSize: 160, scoreThreshold: 0.4 });
        const detections = await faceapi.detectSingleFace(video, options)
          .withFaceLandmarks()
          .withFaceDescriptor();

        if (detections) {
          verified = true;
          status.textContent = "Face detected! Stable... ✅";
          setTimeout(() => {
            stopFaceVerification();
            onSuccess(getDescriptor ? detections.descriptor : null);
          }, 1000);
        } else {
          status.textContent = "Scanning... (Position your face clearly)";
          // Small delay before next check to keep UI responsive
          setTimeout(() => {
            if (videoStream) requestAnimationFrame(checkFace);
          }, 100);
        }
      } catch (e) {
        console.error("Detection error:", e);
        if (videoStream) requestAnimationFrame(checkFace);
      }
    };

    checkFace();

  } catch (err) {
    console.error(err);
    toast("Camera access denied or failed.", "error");
    stopFaceVerification();
  }
}

function stopFaceVerification() {
  const modal = $("#faceModal");
  modal.classList.add("hidden");
  if (videoStream) {
    videoStream.getTracks().forEach(track => track.stop());
    videoStream = null;
  }
}

// ---------- Voting ----------
function hasUserVoted(u) {
  return !!state.userVotes[u];
}
function userChoice(u) {
  return state.userVotes[u];
}

function vote(option) {
  if (!state.user) return toast("Please login first.", "warn");
  if (!state.settings.votingOpen)
    return toast("Voting is currently closed.", "warn");
  if (!state.settings.allowMultipleVotes && hasUserVoted(state.user)) {
    return toast("You have already voted!", "warn");
  }
  if (!state.options.includes(option)) return toast("Invalid option.", "error");

  // Require face verification
  if (state.settings.requireFaceCheck) {
    startFaceVerification(() => finalizeVote(option));
  } else {
    finalizeVote(option);
  }
}

function finalizeVote(option) {
  state.votes[option] = (state.votes[option] || 0) + 1;
  if (!state.settings.allowMultipleVotes) {
    state.userVotes[state.user] = option;
  }
  saveAll();
  renderResultsForUser();
  renderVoteOptions();
  if (state.admin) renderAdmin();
  toast("Thanks for your vote! 🗳️", "success");
}

// ---------- Rendering: User ----------
function renderVoteOptions() {
  const list = $("#vote-options");
  if (!list) return;
  list.innerHTML = "";
  const voted = hasUserVoted(state.user);
  state.options.forEach((opt) => {
    const btn = document.createElement("div");
    btn.className = "option-btn" + (voted ? " disabled" : "");
    btn.innerHTML = `
          <div style="display:flex;align-items:center;gap:10px">
            <span>✅</span><strong>${sanitize(opt)}</strong>
          </div>
          <div style="font-size:12px;color:var(--muted)">
            ${voted ? "Locked" : "Vote"}
          </div>`;
    if (!voted) {
      btn.addEventListener("click", () => vote(opt));
    }
    list.appendChild(btn);
  });

  const info = $("#user-vote-info");
  if (info) {
    if (voted) {
      info.textContent = `You already voted for: ${userChoice(state.user)}`;
    } else {
      info.textContent = "";
    }
  }
}

function renderResultsBars(container, sorted = false) {
  if (!container) return 0;
  container.innerHTML = "";
  const total = Object.values(state.votes).reduce((a, b) => a + b, 0);
  const items = state.options.map((opt) => ({
    opt,
    count: state.votes[opt] || 0,
  }));
  const data = sorted ? items.sort((a, b) => b.count - a.count) : items;

  data.forEach(({ opt, count }) => {
    const pct = percent(count, total);
    const wrap = document.createElement("div");
    wrap.className = "bar";
    wrap.innerHTML = `
          <div class="bar-inner" style="width:${pct}%">
            <strong style="flex:1">${sanitize(opt)}</strong>
            <span>${count} (${pct}%)</span>
          </div>
        `;
    container.appendChild(wrap);
  });

  return total;
}

function renderResultsForUser() {
  const note = $("#results-note");
  const wrap = $("#user-results-wrap");
  if (!wrap) return;

  if (!state.settings.showResultsToUsers) {
    wrap.classList.remove("hidden");
    const resDiv = $("#results");
    if (resDiv) resDiv.innerHTML = "";
    if (note) note.textContent = "Hidden by admin";
    return;
  }
  if (note) note.textContent = "";
  wrap.classList.remove("hidden");
  const resDiv = $("#results");
  if (resDiv) renderResultsBars(resDiv, state.sortByVotes);
}

function renderVoteView() {
  const welcome = $("#welcomeUser");
  if (welcome) welcome.textContent = `Welcome, ${state.user}!`;
  renderVoteOptions();
  renderResultsForUser();
}

// ---------- Rendering: Admin ----------
function renderOptionChips() {
  const chips = $("#option-chips");
  if (!chips) return;
  chips.innerHTML = "";
  state.options.forEach((opt) => {
    const chip = document.createElement("div");
    chip.className = "chip";
    chip.innerHTML = `<span>🏷️</span><span>${sanitize(
      opt
    )}</span><button title="Remove">×</button>`;
    chip.querySelector("button").addEventListener("click", () => {
      // Remove option and its votes
      state.options = state.options.filter((o) => o !== opt);
      delete state.votes[opt];
      // Also clear userVotes pointing to this option
      Object.keys(state.userVotes).forEach((u) => {
        if (state.userVotes[u] === opt) delete state.userVotes[u];
      });
      saveAll();
      renderOptionChips();
      renderAdmin();
      renderVoteOptions();
      renderResultsForUser();
    });
    chips.appendChild(chip);
  });
}

function renderAdmin() {
  // toggles
  const tv = $("#toggleVoting");
  if (tv) tv.checked = !!state.settings.votingOpen;
  const tr = $("#toggleResults");
  if (tr) tr.checked = !!state.settings.showResultsToUsers;
  const tf = $("#toggleFaceCheck");
  if (tf) tf.checked = !!state.settings.requireFaceCheck;

  // results
  const ar = $("#admin-results");
  const total = renderResultsBars(ar, state.sortByVotes);
  const tvLabel = $("#totalVotes");
  if (tvLabel) tvLabel.textContent = `Total votes: ${total}`;

  renderOptionChips();
}

// ---------- Events ----------

// Wrap event listeners in a function to ensure DOM is ready
function initEvents() {
  // Navigation links
  $$(".link").forEach((a) =>
    a.addEventListener("click", (e) => {
      const goto = e.target.getAttribute("data-goto");
      if (goto === "register") switchView("#view-register");
      if (goto === "login") switchView("#view-login");
      if (goto === "admin-login") switchView("#view-admin-login");
    })
  );

  // Buttons & inputs
  const addEv = (id, type, fn) => {
    const el = $(id);
    if (el) el.addEventListener(type, fn);
  };

  addEv("#btnStartFaceReg", "click", startRegistrationScan);
  addEv("#btnCompleteReg", "click", register);
  addEv("#btnLogin", "click", login);
  addEv("#btnAdminLogin", "click", adminLogin);
  addEv("#btnLogoutUser", "click", logoutUser);
  addEv("#btnLogoutAdmin", "click", logoutAdmin);

  addEv("#toggleVoting", "change", (e) => {
    state.settings.votingOpen = e.target.checked;
    saveAll();
    toast(
      state.settings.votingOpen ? "Voting opened." : "Voting closed.",
      "success"
    );
  });

  addEv("#toggleResults", "change", (e) => {
    state.settings.showResultsToUsers = e.target.checked;
    saveAll();
    renderResultsForUser();
    toast(
      state.settings.showResultsToUsers
        ? "Results visible to users."
        : "Results hidden from users.",
      "success"
    );
  });

  addEv("#toggleFaceCheck", "change", (e) => {
    state.settings.requireFaceCheck = e.target.checked;
    saveAll();
    toast(
      state.settings.requireFaceCheck
        ? "Face verification enabled."
        : "Face verification disabled.",
      "success"
    );
  });

  addEv("#btnResetVotes", "click", () => {
    if (!confirm("Reset all votes and clear who voted?")) return;
    Object.keys(state.votes).forEach((k) => (state.votes[k] = 0));
    state.userVotes = {};
    saveAll();
    renderAdmin();
    renderVoteOptions();
    renderResultsForUser();
    toast("Votes reset.", "success");
  });

  addEv("#btnExport", "click", () => {
    const payload = {
      users: state.users,
      votes: state.votes,
      options: state.options,
      userVotes: state.userVotes,
      settings: state.settings,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "votex-data.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    toast("Exported data.", "success");
  });

  addEv("#fileImport", "change", (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result);
        if (!confirm("Import will overwrite current data. Continue?")) return;
        state.users = data.users || {};
        state.votes = data.votes || {};
        state.options = data.options || [];
        state.userVotes = data.userVotes || {};
        state.settings = data.settings || defaults.settings;
        saveAll();
        renderAdmin();
        renderVoteOptions();
        renderResultsForUser();
        toast("Imported data.", "success");
      } catch {
        toast("Invalid JSON file.", "error");
      }
    };
    reader.readAsText(file);
    e.target.value = ""; // reset input
  });

  addEv("#btnAddOption", "click", () => {
    const input = $("#option-input");
    if (!input) return;
    const val = input.value.trim();
    if (!val) return;
    const name = val; // Sanitization happens at render time
    if (state.options.includes(name))
      return toast("Option already exists.", "warn");
    state.options.push(name);
    state.votes[name] = state.votes[name] || 0;
    saveAll();
    input.value = "";
    renderOptionChips();
    renderAdmin();
    renderVoteOptions();
    renderResultsForUser();
    toast("Option added.", "success");
  });

  addEv("#option-input", "keydown", (e) => {
    if (e.key === "Enter") {
      const btn = $("#btnAddOption");
      if (btn) btn.click();
    }
  });

  addEv("#btnSort", "click", () => {
    state.sortByVotes = !state.sortByVotes;
    const btn = $("#btnSort");
    if (btn) {
      btn.textContent = state.sortByVotes
        ? "Sort by original order"
        : "Sort by votes";
    }
    renderAdmin();
    renderResultsForUser();
  });

  // Password UI
  const regPw = $("#reg-password");
  const pwBar = $("#pwStrength");
  if (regPw && pwBar) {
    regPw.addEventListener("input", () => {
      const sc = scorePassword(regPw.value);
      pwBar.style.width = sc + "%";
    });
  }

  function toggleInputType(el) {
    if (!el) return;
    const isPw = el.getAttribute("type") === "password";
    el.setAttribute("type", isPw ? "text" : "password");
  }

  addEv("#toggleRegPass", "click", () => toggleInputType($("#reg-password")));
  addEv("#toggleLoginPass", "click", () =>
    toggleInputType($("#login-password"))
  );
  addEv("#toggleAdminPass", "click", () =>
    toggleInputType($("#admin-password"))
  );

  // Theme toggle
  addEv("#themeToggle", "click", () => {
    const cur = document.documentElement.getAttribute("data-theme");
    setTheme(cur === "light" ? "dark" : "light");
  });

  // Biometric Events
  addEv("#btnRegBiometrics", "click", registerBiometrics);
  addEv("#btnBiometricLogin", "click", loginWithBiometrics);
  addEv("#btnFaceLogin", "click", loginWithFace);
  addEv("#btnCloseFace", "click", stopFaceVerification);

  // Registration Option Toggles
  const setupRegOpt = (boxId, optId, statusId) => {
    const opt = $(optId);
    if (!opt) return;
    opt.addEventListener("click", () => {
      const checkbox = $(boxId);
      checkbox.checked = !checkbox.checked;
      opt.style.borderColor = checkbox.checked ? "var(--primary)" : "var(--border)";
      opt.style.background = checkbox.checked ? "rgba(108, 141, 255, 0.15)" : "var(--card-strong)";
      $(statusId).textContent = checkbox.checked ? "On" : "Off";
      $(statusId).style.color = checkbox.checked ? "var(--primary)" : "var(--muted)";
    });
  };

  setupRegOpt("#check-reg-face", "#opt-reg-face", "#status-reg-face");
  setupRegOpt("#check-reg-bio", "#opt-reg-bio", "#status-reg-bio");
}

// ---------- Startup routing ----------
function boot() {
  initEvents();
  if (state.admin) {
    renderAdmin();
    switchView("#view-admin");
    return;
  }
  if (state.user) {
    renderVoteView();
    switchView("#view-vote");
    return;
  }
  // Default to login
  switchView("#view-login");
}

document.addEventListener("DOMContentLoaded", boot);
