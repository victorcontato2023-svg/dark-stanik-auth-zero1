const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || "secret123";

/* BANCO EM MEMÓRIA */
const codes = [];
const activations = {}; // key -> deviceId

app.get("/", (req,res)=>res.send("Auth server running"));

/* LOGIN ADMIN */
app.post("/admin/login",(req,res)=>{
  const {email,password} = req.body;

  // normaliza para evitar erro por espaço/maiúscula
  const e = String(email || "").trim().toLowerCase();
  const p = String(password || "").trim();

  const adminE = String(ADMIN_EMAIL || "").trim().toLowerCase();
  const adminP = String(ADMIN_PASSWORD || "").trim();

  if(e !== adminE || p !== adminP)
    return res.status(401).json({success:false});

  const token = jwt.sign({role:"admin"},JWT_SECRET,{expiresIn:"12h"});
  res.json({success:true,token});
});

/* MIDDLEWARE ADMIN */
function requireAdmin(req,res,next){
  const t = (req.headers.authorization||"").replace("Bearer ","");
  try{
    const payload = jwt.verify(t,JWT_SECRET);
    if(payload.role!=="admin") throw "";
    next();
  }catch{
    res.status(401).json({error:"unauthorized"});
  }
}

/* GERAR CÓDIGO */
app.post("/admin/generate",requireAdmin,(req,res)=>{
  const code = Math.random().toString(36).substring(2,10).toUpperCase();
  codes.push({code,used:false});
  res.json({code});
});

/* LISTAR CÓDIGOS */
app.get("/admin/codes",requireAdmin,(req,res)=>{
  res.json(codes);
});

/* RESETAR LICENÇA (LIBERAR CÓDIGO PRA OUTRO PC) */
app.post("/admin/reset", requireAdmin, (req, res) => {
  const key = String(req.body?.key || "").trim().toUpperCase();
  if (!key) return res.status(400).json({ error: "missing key" });

  // libera o vínculo do código com o device
  delete activations[key];

  // marca o código como não usado novamente
  const found = codes.find(c => c.code === key);
  if (found) found.used = false;

  res.json({ ok: true, reset: key });
});

/* ATIVAÇÃO */
app.post("/redeem",(req,res)=>{
  const {key,deviceId} = req.body;

  if(!key || !deviceId)
    return res.status(400).json({error:"missing data"});

  const k = String(key).trim().toUpperCase();
  const d = String(deviceId).trim();

  const found = codes.find(c=>c.code===k);

  if(!found || found.used)
    return res.status(400).json({error:"invalid code"});

  if(activations[k])
    return res.status(409).json({error:"code already used on another device"});

  found.used = true;
  activations[k] = d;

  res.json({activated:true});
});

/* VALIDAR LICENÇA */
app.post("/validate",(req,res)=>{
  const {key,deviceId} = req.body;

  const k = String(key || "").trim().toUpperCase();
  const d = String(deviceId || "").trim();

  if(activations[k]===d)
    return res.json({valid:true});

  res.json({valid:false});
});

app.listen(process.env.PORT || 10000,()=>console.log("running"));
