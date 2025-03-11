var express = require('express');
var router = express.Router();
var db = require("../services/db");
var bcrypt = require("bcrypt");

const signupSchema = require("../schemas/signup");
const signinSchema = require("../schemas/signin");

router.get('/', function (req, res, next) {
  res.send('respond with a resource');
});

router.get("/signup", function (req, res, next) {
  res.render("users/signup");
});

router.post("/signup", async function (req, res, next) {
  const result = signupSchema.validate(req.body);

  if (result.error) {
    res.render("users/signup", { error_validation: true });
    return;
  }

  let conn;
  try {
    conn = await db.getConnection();
    const query = "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?);";
    const stmt = await conn.prepare(query);
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const result = await stmt.execute([req.body.name, req.body.email, hashedPassword]);
    res.render("users/signup", { success: true });
  } catch (error) {
    res.render("users/signup", { error_database: true });
  } finally {
    conn.release();
  }
});

router.get("/signin", function (req, res, next) {
  res.render("users/signin");
});

router.post("/signin", async function (req, res, next) {
  const result = signinSchema.validate(req.body);

  if (result.error) {
    res.render("users/signin", { error_validation: true });
    return;
  }

  let conn;
  try {
    conn = await db.getConnection();
    const query = "SELECT password_hash FROM users WHERE email = ?";
    const stmt = await conn.prepare(query);
    const result = await stmt.execute([req.body.email]);

    if (result.length === 0) {
      res.render("users/signin", { unknown_user: true });
      return;
    }

    const hashedPasswordDb = result[0].password_hash;
    const compareResult = await bcrypt.compare(req.body.password, hashedPasswordDb);

    if (!compareResult) {
      res.render("users/signin", { invalid_password: true });
      return;
    }

    res.cookie("express-app-user", req.body.email, {
      maxAge: 1209600000,
      httpOnly: true,
      sameSite: "strict"
    });

    res.redirect("/");
  } catch (error) {
    res.render("users/signin", { error_database: true });
  } finally {
    conn.release();
  }
});

router.get("/signout", function (req, res, next) {
  res.clearCookie("express-app-user");
  res.redirect("/");
});

module.exports = router;
