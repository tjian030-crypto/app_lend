/* ============================================================
   共用程式：Supabase 連線、登入檢查、帳號列、經期紀錄存取
   需先載入 supabase-js，再載入本檔
   注意：這裡只能放 publishable key，絕對不要放 service_role key
   ============================================================ */
var SUPABASE_URL = "https://mtbpasfwppokhtgkvnsn.supabase.co";
var SUPABASE_KEY = "sb_publishable_TqTl_3GwXjlO1SGUUNdUYQ_VwDYl7Ss";

var sb = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

/* ---------- 登入狀態與帳號列 ---------- */
var Auth = (function () {
  var self = { user: null, profile: null };

  // 向 Supabase 驗證目前的登入者，並讀取自己的個人資料（含角色）
  async function loadSession() {
    var res = await sb.auth.getUser();
    if (res.error || !res.data || !res.data.user) return false;
    self.user = res.data.user;

    var p = await sb
      .from("profiles")
      .select("student_id,email,role")
      .eq("id", self.user.id)
      .maybeSingle();
    self.profile = p.data || { student_id: null, email: self.user.email, role: "user" };
    return true;
  }

  // 導覽列最右側：未登入顯示「登入」；登入後變成「使用者」，點開可看到帳號與登出
  function mountNav() {
    var link = document.getElementById("navAuth");
    if (!link) return;
    var li = link.parentNode;

    var style = document.createElement("style");
    style.textContent =
      ".nav-links li.has-menu{position:relative}" +
      ".nav-links .user-menu{position:absolute;right:0;top:calc(100% + 6px);z-index:20;" +
      "width:max-content;min-width:230px;max-width:calc(100vw - 24px);padding:16px;text-align:left;" +
      "border:1px solid var(--line);border-radius:14px;background:var(--surface);" +
      "box-shadow:0 8px 28px rgba(120,90,110,0.18);color:var(--ink)}" +
      ".user-menu .um-label{margin:0 0 6px;font-size:0.8rem;color:var(--muted)}" +
      ".user-menu .um-name{margin:0;font-weight:700;overflow-wrap:anywhere}" +
      ".user-menu .um-sub{margin:2px 0 0;font-size:0.85rem;color:var(--muted);overflow-wrap:anywhere}" +
      ".user-menu .um-role{display:inline-block;margin-top:8px;padding:1px 10px;border-radius:999px;" +
      "background:var(--rose-soft);color:var(--period-ink);font-size:0.8rem}" +
      ".user-menu .um-role.admin{background:var(--lav);color:var(--lav-ink)}" +
      ".nav-links .user-menu a,.user-menu button{display:flex;align-items:center;justify-content:center;" +
      "width:100%;min-height:42px;margin-top:12px;padding:0 14px;border:1.5px solid var(--line);" +
      "border-radius:10px;background:var(--surface);color:var(--ink);font:inherit;font-size:0.95rem;" +
      "text-decoration:none;cursor:pointer}" +
      ".nav-links .user-menu a:hover,.user-menu button:hover{background:var(--bg)}" +
      ".user-menu button.logout{margin-top:10px;background:var(--rose-soft);border-color:var(--rose-soft);" +
      "color:var(--period-ink);font-weight:700}";
    document.head.appendChild(style);

    link.textContent = "使用者";
    link.setAttribute("href", "#");
    link.removeAttribute("aria-current");
    link.setAttribute("aria-haspopup", "true");
    link.setAttribute("aria-expanded", "false");
    li.classList.add("has-menu");

    var menu = document.createElement("div");
    menu.className = "user-menu";
    menu.hidden = true;

    function line(cls, text) {
      var p = document.createElement("p");
      p.className = cls;
      p.textContent = text;
      menu.appendChild(p);
    }

    var isAdmin = self.profile.role === "admin";
    line("um-label", "目前登入的帳號");
    line("um-name", self.profile.student_id || self.profile.email || "");
    if (self.profile.student_id && self.profile.email) line("um-sub", self.profile.email);

    var role = document.createElement("span");
    role.className = "um-role" + (isAdmin ? " admin" : "");
    role.textContent = isAdmin ? "管理者" : "一般使用者";
    menu.appendChild(role);

    if (isAdmin) {
      var admin = document.createElement("a");
      admin.href = "admin.html";
      admin.textContent = "管理後台";
      menu.appendChild(admin);

      var recs = document.createElement("a");
      recs.href = "admin-records.html";
      recs.textContent = "紀錄管理";
      menu.appendChild(recs);
    }

    var out = document.createElement("button");
    out.type = "button";
    out.className = "logout";
    out.textContent = "登出";
    out.addEventListener("click", function () { self.logout(); });
    menu.appendChild(out);

    li.appendChild(menu);

    function setOpen(open) {
      menu.hidden = !open;
      link.setAttribute("aria-expanded", String(open));
    }
    link.addEventListener("click", function (e) {
      e.preventDefault();
      setOpen(menu.hidden);
    });
    document.addEventListener("click", function (e) {
      if (!li.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") setOpen(false);
    });
  }

  // 未登入就導向登入頁；回傳 true 表示可以繼續執行頁面
  self.requireLogin = async function () {
    var ok = await loadSession();
    if (!ok) {
      location.replace("login.html");
      return false;
    }
    mountNav();
    return true;
  };

  // 前端只做介面導向；真正的權限由資料庫 RLS 與管理者函式強制執行
  self.requireAdmin = async function () {
    if (!(await self.requireLogin())) return false;
    if (self.profile.role !== "admin") {
      location.replace("index.html");
      return false;
    }
    return true;
  };

  self.logout = async function () {
    await sb.auth.signOut();
    // 清掉舊版留在這台裝置上的本機資料，避免共用裝置被下一位看到
    try {
      localStorage.removeItem("periodTracker.v1");
      localStorage.removeItem("periodTracker.records.v1");
    } catch (e) {}
    location.replace("login.html");
  };

  return self;
})();

/* ---------- 經期紀錄存取（只處理目前登入者自己的紀錄） ---------- */
var PeriodDB = (function () {
  var TABLE = "period_records";

  function fromRow(r) {
    return {
      id: r.id,
      start: r.start_date,
      end: r.end_date,
      flow: r.flow_level,
      symptoms: Array.isArray(r.symptoms) ? r.symptoms : [],
      mood: r.mood,
      note: r.note || ""
    };
  }

  function toRow(rec) {
    return {
      start_date: rec.start,
      end_date: rec.end,
      flow_level: rec.flow,
      symptoms: rec.symptoms,
      mood: rec.mood,
      note: rec.note || null
    };
  }

  function check(res) {
    if (res.error) throw res.error;
    return res.data;
  }

  return {
    list: async function () {
      // 管理者的帳號能讀到所有人的紀錄，所以這裡一定要限定為自己
      var rows = check(
        await sb.from(TABLE).select("*")
          .eq("user_id", Auth.user.id)
          .order("start_date", { ascending: true })
      );
      return rows.map(fromRow);
    },

    insert: async function (rec) {
      check(await sb.from(TABLE).insert(toRow(rec)));
    },

    update: async function (id, rec) {
      check(await sb.from(TABLE).update(toRow(rec)).eq("id", id).eq("user_id", Auth.user.id));
    },

    remove: async function (id) {
      check(await sb.from(TABLE).delete().eq("id", id).eq("user_id", Auth.user.id));
    },

    errorText: function (err) {
      var msg = (err && err.message) || String(err);
      var code = err && err.code;
      if (/jwt|not authenticated|session/i.test(msg)) return "登入已過期，請重新登入。";
      if (code === "42501" || /row-level security|permission denied/i.test(msg)) {
        return "沒有權限執行這個操作。";
      }
      if (code === "23505") return "這個開始日期已經有紀錄了，請改用「修改」。";
      if (/failed to fetch|networkerror|load failed/i.test(msg)) {
        return "無法連線到 Supabase，請檢查網路連線。";
      }
      return "操作失敗：" + msg;
    },

    banner: function (text) {
      var main = document.querySelector("main");
      if (!main) return;
      var div = document.createElement("div");
      div.setAttribute("role", "alert");
      div.style.cssText =
        "padding:14px 20px;margin-bottom:16px;border-radius:20px;" +
        "background:#f9dce5;color:#4a1f31;font-size:0.95rem;";
      div.textContent = text;
      var hero = main.querySelector(".hero");
      main.insertBefore(div, hero ? hero.nextSibling : main.firstChild);
    }
  };
})();
