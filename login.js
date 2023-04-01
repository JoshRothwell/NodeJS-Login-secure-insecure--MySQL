require("dotenv").config();
const mysql = require("mysql");
const express = require("express");
const bodyParser = require("body-parser");
const xss = require("xss");
const helmet = require("helmet");
const validator = require('validator');

const app = express();
app.use("/assets", express.static("assets"));
app.use(helmet());

// MySQL
const allowedHosts = [process.env.ALLOWED_HOST]; // whitelist allowed hosts
const connection = mysql.createPool({
  connectionLimit: 15,
  port: 4000,
  host: allowedHosts.includes(process.env.DB_HOST) ? process.env.DB_HOST : 'localhost', // check if host is allowed
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  connectTimeout: 100000 // 60 seconds
});

// connect to the database
connection.getConnection(function (error, conn) {
  if (error) throw error;
  else console.log("connected to the database successfully!");
  conn.release();
});

app.get("/", function (req, res) {
  res.sendFile(__dirname + "/index.html");
});

app.post("/", bodyParser.urlencoded({ extended: true }), function (req, res) {
  var username = xss(req.body.username);
  var password = xss(req.body.password);

  // validate user input
  if (!validator.isAlphanumeric(username) || !validator.isAlphanumeric(password)) {
    res.redirect("/");
    return;
  }

  // use prepared statements to prevent SQL injection
  connection.query(
    "select * from loginuser where user_name = ? and user_pass = ?",
    [username, password],
    function (error, results, fields) {
      if (error) throw error;
      if (results.length > 0) {
        res.redirect("/welcome");
      } else {
        res.redirect("/");
      }
      res.end();
    }
  );
});

// when login is success
app.get("/welcome", function (req, res) {
  res.sendFile(__dirname + "/welcome.html");
});

// set app port
app.listen(process.env.PORT || 4000, function () {
    console.log("app listening on port " + (process.env.PORT || 4000));
  });


  
