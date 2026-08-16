import crypto from "node:crypto";

const ADMIN_USER = process.env.ADMIN_USER || "owner";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Yanker@Admin#2026";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-session-secret";
const SUPABASE_URL = String(process.env.SUPABASE_URL || "").replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};

const reply = (statusCode, body) => ({ statusCode, headers, body: JSON.stringify(body) });

function normalizeUsername(value) { return String(value || "").trim().toLowerCase(); }

function normalizeRank(value) {
  const v = String(value ?? "").trim();
  const legacy = { Recruit:"1", Member:"2", Enforcer:"3", Officer:"4", "Co-Owner":"13", Owner:"14" };
  return legacy[v] || (/^(?:[1-9]|1[0-4])$/.test(v) ? v : "1");
}
function rankNumber(value) { return Number(normalizeRank(value)); }
function makeToken(role = "owner", username = ADMIN_USER, rank = 14) {
  const payload = { role, username, rank: rankNumber(rank), exp: Date.now() + 12 * 60 * 60 * 1000 };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function getTokenPayload(event) {
  try {
    const auth = event.headers?.authorization || event.headers?.Authorization || "";
    if (!auth.startsWith("Bearer ")) return null;
    const [encoded, signature] = auth.slice(7).split(".");
    if (!encoded || !signature) return null;
    const expected = crypto.createHmac("sha256", SESSION_SECRET).update(encoded).digest("base64url");
    if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (!payload.exp || payload.exp <= Date.now()) return null;
    return payload;
  } catch { return null; }
}

function checkToken(event) {
  try {
    const auth = event.headers?.authorization || event.headers?.Authorization || "";
    if (!auth.startsWith("Bearer ")) return false;
    const [encoded, signature] = auth.slice(7).split(".");
    if (!encoded || !signature) return false;
    const expected = crypto.createHmac("sha256", SESSION_SECRET).update(encoded).digest("base64url");
    if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return (payload.role === "owner" || (payload.role === "member_admin" && Number(payload.rank) >= 10)) && payload.exp > Date.now();
  } catch { return false; }
}

function isOwnerToken(event) {
  const payload = getTokenPayload(event);
  return !!payload && payload.role === "owner";
}

function isMemberAdminToken(event) {
  const payload = getTokenPayload(event);
  return !!payload && payload.role === "member_admin" && Number(payload.rank) >= 10;
}

function requireOwner(event) {
  return isOwnerToken(event);
}

function getAdminActor(event) {
  const payload = getTokenPayload(event);
  if (!payload) return null;
  if (payload.role === "owner") return { ...payload, isOwner: true };
  if (payload.role === "member_admin" && Number(payload.rank) >= 10) return { ...payload, isOwner: false };
  return null;
}

function requireAdminActor(event) {
  const actor = getAdminActor(event);
  return actor;
}

function dbReady() { return Boolean(SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY); }

async function db(path, options = {}) {
  if (!dbReady()) throw new Error("SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY در Netlify تنظیم نشده‌اند.");
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { message: text }; }
  if (!response.ok) {
    console.error("SUPABASE_ERROR", response.status, data);
    throw new Error(data?.message || data?.error_description || `Supabase error ${response.status}`);
  }
  return data;
}

function mapRequest(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    username: r.username,
    passwordHash: r.password_hash || "",
    discord: r.discord || "",
    cityAge: Number(r.city_age || 0),
    realAge: Number(r.real_age || 0),
    playtime: Number(r.playtime || 0),
    reason: r.reason || "",
    status: r.status || "pending",
    createdAt: Number(r.created_at || 0),
    reviewedBy: r.reviewed_by || null,
    reviewedAt: r.reviewed_at ? Number(r.reviewed_at) : null,
    rank: r.rank || null
  };
}

function mapMember(m, includeSecret = false) {
  if (!m) return null;
  const out = {
    id: m.id,
    name: m.name,
    username: m.username,
    discord: m.discord || "",
    rank: normalizeRank(m.rank),
    status: m.status || "online",
    joinedAt: Number(m.joined_at || 0),
    sourceRequestId: m.source_request_id || null
  };
  if (includeSecret) out.passwordHash = m.password_hash || "";
  return out;
}

async function getRequestsFor(username = null) {
  const path = username
    ? `requests?username=eq.${encodeURIComponent(username)}&order=created_at.desc`
    : `requests?select=*&order=created_at.desc`;
  return (await db(path) || []).map(mapRequest);
}

async function getMembers() {
  return (await db(`members?select=*&order=joined_at.desc`) || []).map(m => mapMember(m, false));
}


function mapAnnouncement(a){
  if(!a) return null;
  return { id:a.id, title:a.title||"", body:a.body||"", author:a.author||"", date:Number(a.created_at||0), published:a.published!==false };
}
function mapTicket(t, messages=[]){
  return { id:t.id, username:t.username||"", name:t.name||"", subject:t.subject||"", category:t.category||"member", status:t.status||"open", createdAt:Number(t.created_at||0), updatedAt:Number(t.updated_at||t.created_at||0), messages };
}
function mapTicketMessage(m){
  return { id:m.id, ticketId:m.ticket_id, sender:m.sender||"user", senderName:m.sender_name||"", body:m.body||"", createdAt:Number(m.created_at||0) };
}
async function getAnnouncements(){
  return (await db("announcements?select=*&order=created_at.desc") || []).map(mapAnnouncement);
}
async function getTickets(username=null){
  const q = username ? `tickets?username=eq.${encodeURIComponent(username)}&order=updated_at.desc` : "tickets?select=*&order=updated_at.desc";
  const tickets = await db(q) || [];
  if(!tickets.length) return [];
  const ids=tickets.map(t=>t.id);
  const messages=await db(`ticket_messages?ticket_id=in.(${ids.map(encodeURIComponent).join(',')})&order=created_at.asc`) || [];
  return tickets.map(t=>mapTicket(t,messages.filter(m=>m.ticket_id===t.id).map(mapTicketMessage)));
}

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return reply(204, {});
  const action = event.queryStringParameters?.action || "";
  let body = {};
  try { if (event.body) body = JSON.parse(event.body); }
  catch { return reply(400, { ok: false, error: "JSON نامعتبر است." }); }

  try {
    if (event.httpMethod === "GET" && action === "health") {
      return reply(200, { ok: true, service: "yanker-api", storage: "supabase", persistentStorage: dbReady() });
    }

    if (!dbReady()) return reply(500, { ok: false, error: "اتصال Supabase در Environment Variables نتلیفای تنظیم نشده است." });

    if (event.httpMethod === "POST" && action === "login") {
      if (normalizeUsername(body.username) !== normalizeUsername(ADMIN_USER) || String(body.password || "") !== ADMIN_PASSWORD)
        return reply(401, { ok: false, error: "نام کاربری یا رمز عبور اشتباه است." });
      return reply(200, { ok: true, token: makeToken() });
    }

    if (event.httpMethod === "POST" && action === "request") {
      const name = String(body.name || "").trim();
      const username = normalizeUsername(body.username);
      const discord = String(body.discord || "").trim();
      const passwordHash = String(body.passwordHash || "").trim();
      const reason = String(body.reason || "").trim();
      if (!name || !username || !discord || !reason) return reply(400, { ok: false, error: "اطلاعات ضروری کامل نیست." });

      const members = await db(`members?select=id,username&username=eq.${encodeURIComponent(username)}&limit=1`);
      if (members?.length) return reply(409, { ok: false, error: "این کاربر قبلاً عضو رسمی است." });
      const pending = await db(`requests?select=id&username=eq.${encodeURIComponent(username)}&status=eq.pending&limit=1`);
      if (pending?.length) return reply(409, { ok: false, error: "شما یک درخواست در انتظار بررسی دارید." });

      const request = {
        id: crypto.randomUUID(), name, username, password_hash: passwordHash, discord,
        city_age: Number(body.cityAge) || 0, real_age: Number(body.realAge) || 0,
        playtime: Number(body.playtime) || 0, reason, status: "pending", created_at: Date.now(),
        reviewed_by: null, reviewed_at: null, rank: null
      };
      const inserted = await db("requests", { method: "POST", headers: { Prefer: "return=representation" }, body: JSON.stringify(request) });
      return reply(201, { ok: true, request: mapRequest(inserted?.[0] || request) });
    }

    if (event.httpMethod === "GET" && action === "my-status") {
      const username = normalizeUsername(event.queryStringParameters?.username);
      if (!username) return reply(400, { ok: false, error: "نام کاربری لازم است." });
      const requests = await getRequestsFor(username);
      const members = await db(`members?username=eq.${encodeURIComponent(username)}&limit=1`);
      return reply(200, { ok: true, requests, member: mapMember(members?.[0] || null, false) });
    }

    if (event.httpMethod === "POST" && action === "member-login") {
      const username = normalizeUsername(body.username);
      const passwordHash = crypto.createHash("sha256").update(String(body.password || "")).digest("hex");
      const rows = await db(`members?username=eq.${encodeURIComponent(username)}&password_hash=eq.${encodeURIComponent(passwordHash)}&limit=1`);
      if (!rows?.length) return reply(401, { ok: false, error: "نام کاربری یا رمز عبور اشتباه است." });
      const member = mapMember(rows[0], false);
      const adminToken = rankNumber(member.rank) >= 10 ? makeToken("member_admin", member.username, member.rank) : null;
      return reply(200, { ok: true, member, adminToken });
    }

    // User login works across devices by checking the persistent member/request records.
    // This is a fallback for accounts whose old localStorage user record is missing.
    if (event.httpMethod === "POST" && action === "user-register") {
      const username=normalizeUsername(body.username), displayName=String(body.displayName||"").trim(), passwordHash=String(body.passwordHash||"").trim();
      if(!username||!displayName||!passwordHash) return reply(400,{ok:false,error:"اطلاعات ثبت‌نام کامل نیست."});
      const exists=await db(`site_users?username=eq.${encodeURIComponent(username)}&limit=1`);
      const member=await db(`members?username=eq.${encodeURIComponent(username)}&limit=1`);
      if(exists?.length||member?.length) return reply(409,{ok:false,error:"این نام کاربری قبلاً ثبت شده است."});
      const row={id:crypto.randomUUID(),username,display_name:displayName,password_hash:passwordHash,role:"user",created_at:Date.now()};
      const out=await db("site_users",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify(row)});
      return reply(201,{ok:true,user:{id:row.id,username,displayName,role:"user",createdAt:row.created_at}});
    }

    if (event.httpMethod === "POST" && action === "user-login") {
      const username = normalizeUsername(body.username);
      const passwordHash = crypto.createHash("sha256").update(String(body.password || "")).digest("hex");
      if (!username || !passwordHash) return reply(400, { ok:false, error:"اطلاعات ورود کامل نیست." });
      const members = await db(`members?username=eq.${encodeURIComponent(username)}&password_hash=eq.${encodeURIComponent(passwordHash)}&limit=1`);
      if (members?.length) {
        const m = members[0];
        const member = mapMember(m,false);
        const adminToken = rankNumber(member.rank) >= 10 ? makeToken("member_admin", member.username, member.rank) : null;
        return reply(200, { ok:true, user:{ username:m.username, displayName:m.name || m.username, role:"member" }, member, adminToken });
      }
      const siteUsers = await db(`site_users?username=eq.${encodeURIComponent(username)}&password_hash=eq.${encodeURIComponent(passwordHash)}&limit=1`);
      if(siteUsers?.length){
        const u=siteUsers[0];
        return reply(200,{ok:true,user:{username:u.username,displayName:u.display_name||u.username,role:"user"}});
      }
      const requests = await db(`requests?username=eq.${encodeURIComponent(username)}&password_hash=eq.${encodeURIComponent(passwordHash)}&order=created_at.desc&limit=1`);
      if (requests?.length) {
        const r = requests[0];
        return reply(200, { ok:true, user:{ username:r.username, displayName:r.name || r.username, role:"user" }, request:mapRequest(r) });
      }
      return reply(401, { ok:false, error:"نام کاربری یا رمز عبور اشتباه است." });
    }

    if (event.httpMethod === "GET" && action === "members") return reply(200, { ok: true, members: await getMembers() });

    if (event.httpMethod === "GET" && action === "announcements") return reply(200, { ok: true, announcements: await getAnnouncements() });

    if (event.httpMethod === "POST" && action === "ticket-create") {
      const username = normalizeUsername(body.username);
      const name = String(body.name || "").trim();
      let subject = String(body.subject || "").trim();
      const message = String(body.message || "").trim();
      if(!username || !name || !message) return reply(400,{ok:false,error:"اطلاعات تیکت کامل نیست."});
      const memberRows = await db(`members?username=eq.${encodeURIComponent(username)}&limit=1`);
      const requestRows = await db(`requests?username=eq.${encodeURIComponent(username)}&order=created_at.desc&limit=1`);
      const userRows = await db(`site_users?username=eq.${encodeURIComponent(username)}&limit=1`);
      const isMember = !!memberRows?.length;
      const isRegistered = isMember || !!requestRows?.length || !!userRows?.length;
      if(!isRegistered) return reply(403,{ok:false,error:"ابتدا در سایت ثبت‌نام کنید."});
      const category = isMember ? "member" : "cafe";
      if(category === "cafe") subject = "کافه";
      if(!subject) return reply(400,{ok:false,error:"موضوع تیکت الزامی است."});

      // Anti-spam cooldown: each user can open a new ticket only 10 seconds
      // after their most recently created ticket (including tickets sent by admin).
      const latest = await db(`tickets?username=eq.${encodeURIComponent(username)}&select=created_at&order=created_at.desc&limit=1`);
      const now=Date.now();
      const lastCreated = Number(latest?.[0]?.created_at || 0);
      const remaining = 10000 - (now - lastCreated);
      if(lastCreated && remaining > 0){
        return reply(429,{ok:false,error:`برای ارسال تیکت بعدی ${Math.ceil(remaining/1000)} ثانیه صبر کنید.`,retryAfter:Math.ceil(remaining/1000)});
      }

      const id=crypto.randomUUID();
      const ticket={id,username,name,subject,category,status:"open",created_at:now,updated_at:now};
      await db("tickets",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify(ticket)});
      await db("ticket_messages",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify({id:crypto.randomUUID(),ticket_id:id,sender:"user",sender_name:name,body:message,created_at:now})});
      const tickets=await getTickets(username);
      return reply(201,{ok:true,ticket:tickets[0],cooldown:10});
    }

    if (event.httpMethod === "POST" && action === "ticket-create-admin") {
      const username=normalizeUsername(body.username);
      const subject=String(body.subject||"").trim();
      const message=String(body.message||"").trim();
      if(!username||!subject||!message) return reply(400,{ok:false,error:"کاربر، موضوع و متن تیکت الزامی است."});
      const members=await db(`members?username=eq.${encodeURIComponent(username)}&select=id,username,name&limit=1`);
      if(!members?.length) return reply(404,{ok:false,error:"عضو موردنظر پیدا نشد."});
      const member=members[0];
      const now=Date.now(), id=crypto.randomUUID();
      const ticket={id,username:member.username,name:member.name||member.username,subject,category:"member",status:"answered",created_at:now,updated_at:now};
      await db("tickets",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify(ticket)});
      await db("ticket_messages",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify({id:crypto.randomUUID(),ticket_id:id,sender:"admin",sender_name:ADMIN_USER,body:message,created_at:now})});
      const tickets=await getTickets(member.username);
      return reply(201,{ok:true,ticket:tickets[0]});
    }

    if (event.httpMethod === "GET" && action === "tickets") {
      const username=normalizeUsername(event.queryStringParameters?.username);
      if(!username) return reply(400,{ok:false,error:"نام کاربری لازم است."});
      return reply(200,{ok:true,tickets:await getTickets(username)});
    }
    if (event.httpMethod === "POST" && action === "ticket-close-own") {
      const id=String(body.id||""), username=normalizeUsername(body.username);
      if(!id||!username) return reply(400,{ok:false,error:"اطلاعات تیکت نامعتبر است."});
      const rows=await db(`tickets?id=eq.${encodeURIComponent(id)}&username=eq.${encodeURIComponent(username)}&limit=1`);
      if(!rows?.length) return reply(404,{ok:false,error:"تیکت پیدا نشد."});
      await db(`tickets?id=eq.${encodeURIComponent(id)}&username=eq.${encodeURIComponent(username)}`,{method:"PATCH",body:JSON.stringify({status:"closed",updated_at:Date.now()})});
      return reply(200,{ok:true});
    }

    if (event.httpMethod === "POST" && action === "ticket-reply") {
      const id=String(body.id||""), text=String(body.message||"").trim();
      const username=normalizeUsername(body.username);

      if(!id||!text) return reply(400,{ok:false,error:"پیام پاسخ الزامی است."});

      const ticketRows=await db(`tickets?id=eq.${encodeURIComponent(id)}&limit=1`);
      if(!ticketRows?.length) return reply(404,{ok:false,error:"تیکت پیدا نشد."});

      const ticket=ticketRows[0];
      const now=Date.now();

      // پیام عضو به مدیریت (فقط داخل تیکت خودش)
      if(username){
        if(normalizeUsername(ticket.username)!==username)
          return reply(403,{ok:false,error:"این تیکت متعلق به شما نیست."});

        await db("ticket_messages",{
          method:"POST",
          headers:{Prefer:"return=representation"},
          body:JSON.stringify({
            id:crypto.randomUUID(),
            ticket_id:id,
            sender:"user",
            sender_name:ticket.name || username,
            body:text,
            created_at:now
          })
        });

        await db(`tickets?id=eq.${encodeURIComponent(id)}`,{
          method:"PATCH",
          body:JSON.stringify({status:"open",updated_at:now})
        });

        return reply(200,{ok:true,ticket:(await getTickets(username))[0]});
      }

      // پاسخ مدیریت: تیکت‌های کافه فقط برای Rank 12+
      const actor=getAdminActor(event);
      if(!actor) return reply(401,{ok:false,error:"دسترسی مدیریت لازم است."});
      if(!actor.isOwner && Number(actor.rank)<11) return reply(403,{ok:false,error:"پاسخ‌گویی تیکت‌ها از رنک 11 به بالا است."});
      if(ticket.category === "cafe" && !actor.isOwner && Number(actor.rank)<12) return reply(403,{ok:false,error:"تیکت‌های کافه فقط برای رنک 12 به بالا قابل مشاهده و پاسخ هستند."});
      await db("ticket_messages",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify({
        id:crypto.randomUUID(),
        ticket_id:id,
        sender:"admin",
        sender_name:ADMIN_USER,
        body:text,
        created_at:now
      })});

      await db(`tickets?id=eq.${encodeURIComponent(id)}`,{method:"PATCH",body:JSON.stringify({status:"answered",updated_at:now})});
      return reply(200,{ok:true,ticket:(await getTickets())[0]});
    }

    if (!checkToken(event)) return reply(401, { ok: false, error: "دسترسی مدیریت لازم است." });

    // Rank 10+ members get a separate, passwordless admin panel.
    // Their scope is intentionally limited to tickets, membership approval/deletion,
    // and assigning ranks up to 6. Owner keeps full access to the original panel.
    const ownerOnlyActions = new Set([
      "stats", "announcements", "announcement-create", "announcement-update",
      "announcement-delete"
    ]);
    if (isMemberAdminToken(event) && ownerOnlyActions.has(action)) {
      return reply(403, { ok: false, error: "این بخش فقط برای Owner در دسترس است." });
    }

    if (isMemberAdminToken(event) && Number(getTokenPayload(event)?.rank||0)<11 && !["penalties","penalty-create","penalty-delete"].includes(action)) {
      return reply(403,{ok:false,error:"رنک 10 فقط به پنل جریمه‌ها دسترسی دارد."});
    }

    if (event.httpMethod === "GET" && action === "requests") return reply(200, { ok: true, requests: await getRequestsFor() });

    if (event.httpMethod === "GET" && action === "stats") {
      const requests = await getRequestsFor();
      const members = await getMembers();
      return reply(200, { ok: true, stats: {
        totalRequests: requests.length,
        pending: requests.filter(r => r.status === "pending").length,
        approved: requests.filter(r => r.status === "approved").length,
        rejected: requests.filter(r => r.status === "rejected").length,
        members: members.length
      }});
    }


    if (event.httpMethod === "POST" && action === "announcement-create") {
      const title=String(body.title||"").trim(), text=String(body.body||"").trim();
      if(!title||!text) return reply(400,{ok:false,error:"عنوان و متن اطلاعیه الزامی است."});
      const row={id:crypto.randomUUID(),title,body:text,author:ADMIN_USER,created_at:Date.now(),published:true};
      const out=await db("announcements",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify(row)});
      return reply(201,{ok:true,announcement:mapAnnouncement(out?.[0]||row)});
    }
    if (event.httpMethod === "POST" && action === "announcement-update") {
      const id=String(body.id||""), title=String(body.title||"").trim(), text=String(body.body||"").trim();
      if(!id||!title||!text) return reply(400,{ok:false,error:"اطلاعات اطلاعیه کامل نیست."});
      const out=await db(`announcements?id=eq.${encodeURIComponent(id)}`,{method:"PATCH",headers:{Prefer:"return=representation"},body:JSON.stringify({title,body:text})});
      return reply(200,{ok:true,announcement:mapAnnouncement(out?.[0])});
    }
    if (event.httpMethod === "POST" && action === "announcement-delete") {
      const id=String(body.id||""); if(!id) return reply(400,{ok:false,error:"شناسه اطلاعیه نامعتبر است."});
      await db(`announcements?id=eq.${encodeURIComponent(id)}`,{method:"DELETE"}); return reply(200,{ok:true});
    }
    if (event.httpMethod === "GET" && action === "tickets-admin") {
      const actor=getAdminActor(event);
      if(!actor) return reply(401,{ok:false,error:"دسترسی مدیریت لازم است."});
      const all=await getTickets();
      const visible=actor.isOwner ? all : all.filter(t=>t.category !== "cafe" || Number(actor.rank)>=12);
      return reply(200,{ok:true,tickets:visible});
    }
    if (event.httpMethod === "POST" && action === "ticket-close") {
      const id=String(body.id||""); if(!id) return reply(400,{ok:false,error:"شناسه تیکت نامعتبر است."});
      const actor=getAdminActor(event); const rows=await db(`tickets?id=eq.${encodeURIComponent(id)}&limit=1`);
      if(!rows?.length) return reply(404,{ok:false,error:"تیکت پیدا نشد."});
      if(!actor?.isOwner && rows[0].category==="cafe" && Number(actor?.rank)<12) return reply(403,{ok:false,error:"دسترسی تیکت کافه فقط برای رنک 12+ است."});
      await db(`tickets?id=eq.${encodeURIComponent(id)}`,{method:"PATCH",body:JSON.stringify({status:"closed",updated_at:Date.now()})}); return reply(200,{ok:true});
    }
    if (event.httpMethod === "POST" && action === "ticket-delete") {
      const id=String(body.id||""); if(!id) return reply(400,{ok:false,error:"شناسه تیکت نامعتبر است."});
      const rows=await db(`tickets?id=eq.${encodeURIComponent(id)}&limit=1`);
      if(!rows?.length) return reply(404,{ok:false,error:"تیکت پیدا نشد."});
      const actor=getAdminActor(event);
      if(!actor?.isOwner && rows[0].category==="cafe" && Number(actor?.rank)<12) return reply(403,{ok:false,error:"دسترسی تیکت کافه فقط برای رنک 12+ است."});
      await db(`ticket_messages?ticket_id=eq.${encodeURIComponent(id)}`,{method:"DELETE"});
      await db(`tickets?id=eq.${encodeURIComponent(id)}`,{method:"DELETE"});
      return reply(200,{ok:true});
    }

    if (event.httpMethod === "POST" && action === "review") {
      const id = String(body.id || "");
      const decision = body.decision;
      if (isMemberAdminToken(event) && decision !== "approve") {
        return reply(403, { ok:false, error:"پنل رنک 11+ فقط امکان قبول کردن اعضا را دارد." });
      }
      if (!id || !["approve", "reject"].includes(decision)) return reply(400, { ok: false, error: "درخواست یا تصمیم نامعتبر است." });
      const rows = await db(`requests?id=eq.${encodeURIComponent(id)}&limit=1`);
      const request = rows?.[0];
      if (!request) return reply(404, { ok: false, error: "درخواست پیدا نشد." });
      if (request.status !== "pending") return reply(409, { ok: false, error: "این درخواست قبلاً بررسی شده است." });

      const reviewedAt = Date.now();
      const updated = await db(`requests?id=eq.${encodeURIComponent(id)}`, {
        method: "PATCH", headers: { Prefer: "return=representation" },
        body: JSON.stringify({ status: decision === "approve" ? "approved" : "rejected", reviewed_by: ADMIN_USER, reviewed_at: reviewedAt })
      });
      let member = null;
      if (decision === "approve") {
        const existing = await db(`members?username=eq.${encodeURIComponent(request.username)}&limit=1`);
        if (existing?.length) {
          const m = await db(`members?id=eq.${encodeURIComponent(existing[0].id)}`, {
            method: "PATCH", headers: { Prefer: "return=representation" },
            body: JSON.stringify({ name: request.name, discord: request.discord, password_hash: request.password_hash || existing[0].password_hash, status: "online" })
          });
          member = mapMember(m?.[0] || existing[0], false);
        } else {
          const m = await db("members", {
            method: "POST", headers: { Prefer: "return=representation" },
            body: JSON.stringify({ id: crypto.randomUUID(), name: request.name, username: request.username, password_hash: request.password_hash || "", discord: request.discord, rank: normalizeRank(request.rank || "1"), status: "online", joined_at: Date.now() })
          });
          member = mapMember(m?.[0], false);
        }
      }
      return reply(200, { ok: true, request: mapRequest(updated?.[0] || { ...request, status: decision === "approve" ? "approved" : "rejected", reviewed_by: ADMIN_USER, reviewed_at: reviewedAt }), member });
    }

    if (event.httpMethod === "POST" && action === "member-rank") {
      const actor = requireAdminActor(event);
      if (!actor) return reply(401, {ok:false,error:"دسترسی مدیریت لازم است."});
      const id = String(body.id || "");
      const rank = normalizeRank(body.rank);
      if(!/^(?:[1-9]|1[0-4])$/.test(rank)) return reply(400, { ok:false, error:"رنک باید بین 1 تا 14 باشد." });
      const rows = await db(`members?id=eq.${encodeURIComponent(id)}&limit=1`);
      if (!rows?.length) return reply(404, { ok: false, error: "عضو پیدا نشد." });
      const targetRank = rankNumber(rows[0].rank);
      if (!actor.isOwner) {
        if (targetRank >= 11) return reply(403, {ok:false,error:"اعضای رنک 11 به بالا قابل تغییر نیستند."});
        if (rankNumber(rank) > 6) return reply(403, {ok:false,error:"این پنل فقط می‌تواند رنک 1 تا 6 بدهد."});
      }
      const updated = await db(`members?id=eq.${encodeURIComponent(id)}`, { method: "PATCH", headers: { Prefer: "return=representation" }, body: JSON.stringify({ rank }) });
      return reply(200, { ok: true, member: mapMember(updated?.[0] || { ...rows[0], rank }, false) });
    }

    if (event.httpMethod === "POST" && action === "request-delete") {
      if (isMemberAdminToken(event)) return reply(403, { ok:false, error:"حذف درخواست فقط برای Owner است." });
      const id = String(body.id || "");
      if (!id) return reply(400, { ok: false, error: "شناسه درخواست نامعتبر است." });
      const rows = await db(`requests?id=eq.${encodeURIComponent(id)}&limit=1`);
      if (!rows?.length) return reply(404, { ok: false, error: "درخواست پیدا نشد." });
      await db(`requests?id=eq.${encodeURIComponent(id)}`, { method: "DELETE" });
      return reply(200, { ok: true });
    }

    if (event.httpMethod === "POST" && action === "member-delete") {
      const actor = requireAdminActor(event);
      if (!actor) return reply(401, {ok:false,error:"دسترسی مدیریت لازم است."});
      const id = String(body.id || "");
      const rows = await db(`members?id=eq.${encodeURIComponent(id)}&limit=1`);
      if (!rows?.length) return reply(404, { ok: false, error: "عضو پیدا نشد." });
      if (!actor.isOwner && rankNumber(rows[0].rank) >= 11) return reply(403, {ok:false,error:"اعضای رنک 11 به بالا قابل حذف یا تغییر نیستند."});
      await db(`members?id=eq.${encodeURIComponent(id)}`, { method: "DELETE" });
      return reply(200, { ok: true });
    }


    if (event.httpMethod === "GET" && action === "penalties") {
      const actor=getAdminActor(event); if(!actor || (!actor.isOwner && Number(actor.rank)<10)) return reply(403,{ok:false,error:"پنل جریمه فقط برای رنک 10 به بالا است."});
      const rows=await db("penalties?select=*&order=created_at.desc");
      return reply(200,{ok:true,penalties:(rows||[]).map(p=>({id:p.id,username:p.username||"",name:p.name||"",reason:p.reason||"",amount:Number(p.amount||0),createdAt:Number(p.created_at||0),issuedBy:p.issued_by||""}))});
    }
    if (event.httpMethod === "POST" && action === "penalty-create") {
      const actor=getAdminActor(event); if(!actor || (!actor.isOwner && Number(actor.rank)<10)) return reply(403,{ok:false,error:"پنل جریمه فقط برای رنک 10 به بالا است."});
      const username=normalizeUsername(body.username), reason=String(body.reason||"").trim(), amount=Number(body.amount)||0;
      if(!username||!reason) return reply(400,{ok:false,error:"عضو و دلیل جریمه الزامی است."});
      const rows=await db(`members?username=eq.${encodeURIComponent(username)}&limit=1`); if(!rows?.length) return reply(404,{ok:false,error:"عضو تأییدشده پیدا نشد."});
      const row={id:crypto.randomUUID(),username,name:rows[0].name||username,reason,amount,issued_by:actor.username||ADMIN_USER,created_at:Date.now()};
      const out=await db("penalties",{method:"POST",headers:{Prefer:"return=representation"},body:JSON.stringify(row)});
      return reply(201,{ok:true,penalty:out?.[0]||row});
    }
    if (event.httpMethod === "POST" && action === "penalty-delete") {
      const actor=getAdminActor(event); if(!actor || (!actor.isOwner && Number(actor.rank)<10)) return reply(403,{ok:false,error:"پنل جریمه فقط برای رنک 10 به بالا است."});
      const id=String(body.id||""); if(!id) return reply(400,{ok:false,error:"شناسه جریمه نامعتبر است."});
      await db(`penalties?id=eq.${encodeURIComponent(id)}`,{method:"DELETE"}); return reply(200,{ok:true});
    }

    return reply(404, { ok: false, error: "مسیر پیدا نشد." });
  } catch (error) {
    console.error("YANKER_FATAL_ERROR", error);
    return reply(500, { ok: false, error: error?.message || "خطای داخلی سرور." });
  }
}
