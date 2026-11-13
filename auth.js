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

  // 帳號列放在 .hero 內，顯示目前登入者；登出入口在導覽列
  function mountBar() {
    var hero = document.querySelector(".hero");
    if (!hero || document.querySelector(".account-bar")) return;

    var style = document.createElement("style");
    style.textContent =
      ".account-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin-top:12px;" +
      "padding:10px 16px;border-radius:14px;background:var(--lav-soft);font-size:0.9rem;color:var(--ink)}" +
      ".account-bar .who{flex:1;min-width:0;overflow-wrap:anywhere}" +
      ".account-bar a,.account-bar button{display:inline-flex;align-items:center;min-height:36px;" +
      "padding:0 14px;border:1.5px solid var(--line);border-radius:10px;background:var(--surface);" +
      "color:var(--ink);font:inherit;text-decoration:none;cursor:pointer}" +
      ".account-bar a:hover,.account-bar button:hover{background:var(--bg)}";
    document.head.appendChild(style);

    var bar = document.createElement("div");
    bar.className = "account-bar";

    var who = document.createElement("span");
    who.className = "who";
    who.textContent =
      "已登入：" + (self.profile.student_id || self.profile.email || "") +
      (self.profile.role === "admin" ? "（管理者）" : "");
    bar.appendChild(who);

    if (self.profile.role === "admin") {
      var link = document.createElement("a");
      link.href = "admin.html";
      link.textContent = "管理後台";
      bar.appendChild(link);
    }

    hero.appendChild(bar);
  }

  // 導覽列最右邊的入口：未登入顯示「登入」，登入後變成「登出」
  function mountNav(loggedIn) {
    var link = document.getElementById("navAuth");
    if (!link || !loggedIn) return;
    link.textContent = "登出";
    link.setAttribute("href", "#");
    link.removeAttribute("aria-current");
    link.addEventListener("click", function (e) {
      e.preventDefault();
      self.logout();
    });
  }

  // 未登入就導向登入頁；回傳 true 表示可以繼續執行頁面
  self.requireLogin = async function () {
    var ok = await loadSession();
    if (!ok) {
      location.replace("login.html");
      return false;
    }
    mountBar();
    mountNav(true);
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
