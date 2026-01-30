const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const issuedCodes = new Set();
const usedCodes = new Set();
const activations = new Map();

app.get("/", (req, res) => res.send("Auth server running"));

app.post("/admin/login", (req, res) => {
  const { email, password } = req.body || {};
  const ok = email === ADMIN_EMAIL && password === ADMIN_PASSWORD;

  if (!ok) return res.status(401).json({ success:false });

  const token = jwt.sign({ role:"admin" }, JWT_SECRET, { expiresIn:"12h" });
  res.json({ success:true, token });
});

function requireAdmin(req,res,next){
  const t = (req.headers.authorization||"").replace("Bearer ","");
  if(!t) return res.status(401).end();

  try{
    const p = jwt.verify(t, JWT_SECRET);
    if(p.role!=="admin") return res.status(403).end();
    next();
  }catch{
    res.status(401).end();
  }
}

app.post("/admin/generate", requireAdmin,(req,res)=>{
  const code = makeCode();
  issuedCodes.add(code);
  res.json({ code });
});

app.post("/redeem",(req,res)=>{
  const { code, deviceId } = req.body||{};
  if(!issuedCodes.has(code)) return res.status(400).end();
  if(usedCodes.has(code)) return res.status(409).end();

  usedCodes.add(code);
  activations.set(deviceId,{date:new Date().toISOString()});
  res.json({ activated:true });
});

app.get("/status",(req,res)=>{
  const d = activations.get(req.query.deviceId);
  res.json({ activated:!!d });
});

function makeCode(){
  const c="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b=()=>Array.from({length:4},()=>c[Math.floor(Math.random()*c.length)]).join("");
  return `${b()}-${b()}-${b()}`;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log("running",PORT));
