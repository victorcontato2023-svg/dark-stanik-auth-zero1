const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

const codes = [];
const activations = {};

app.get("/", (req,res)=>res.send("Auth server running"));

/* LOGIN ADMIN */
app.post("/admin/login",(req,res)=>{
  const {email,password} = req.body;

  if(email!==ADMIN_EMAIL || password!==ADMIN_PASSWORD)
    return res.status(401).json({success:false});

  const token = jwt.sign({role:"admin"},JWT_SECRET,{expiresIn:"12h"});
  res.json({success:true,token});
});

/* MIDDLEWARE ADMIN */
function requireAdmin(req,res,next){
  const t = (req.headers.authorization||"").replace("Bearer ","");
  try{
    const p = jwt.verify(t,JWT_SECRET);
    if(p.role!=="admin") throw "";
    next();
  }catch{
    res.status(401).end();
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

/* ATIVAÇÃO (1 PC) */
app.post("/redeem",(req,res)=>{
  const {code,deviceId} = req.body;

  const found = codes.find(c=>c.code===code);

  if(!found || found.used)
    return res.status(400).json({error:"invalid code"});

  if(activations[deviceId])
    return res.status(409).json({error:"device already used"});

  found.used = true;
  activations[deviceId] = true;

  res.json({activated:true});
});

app.listen(process.env.PORT || 10000,()=>console.log("running"));
