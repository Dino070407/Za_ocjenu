var express = require('express');
var router = express.Router();
var db = require("../services/db");

/* GET home page. */
router.get('/', async function (req, res, next) {

  let conn;
  try {
    conn = await db.getConnection();
    const query = "SELECT * FROM rooms ORDER BY name;";
    const stmt = await conn.prepare(query);
    const result = await stmt.execute();
    res.render('index', { items: result });
  } catch (error) {
  } finally {
    conn.release();
  }
});

module.exports = router;
