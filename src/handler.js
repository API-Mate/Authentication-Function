'use strict'

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
let res = { status: 400, message: "error occured" };

module.exports = async (event, context) => {
  try {
    if (event.method === 'OPTIONS') {
      var headers = {};
      headers["Access-Control-Allow-Origin"] = "http://localhost:3000";
      headers["Access-Control-Allow-Methods"] = "POST, GET, PUT, OPTIONS";
      headers["Access-Control-Allow-Credentials"] = false;
      headers["Access-Control-Max-Age"] = '86400'; // 24 hours
      headers["Access-Control-Allow-Headers"] = "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept";
      return context
        .status(200)
        .headers(headers)
        .succeed();
    } else {
      const action = event.body.action;
      const data = event.body.data;
      let ret;

      if (action == "login")
        ret = await login(data);
      else
        ret = await register(data);

      return context
        .status(ret.status)
        .headers({
          "Content-type": "application/json; charset=utf-8",
          "Access-Control-Allow-Origin": "http://localhost:3000"
        })
        .succeed(ret.message);
    }
  } catch (error) {
    return context
      .status(500)
      .headers({
        "Access-Control-Allow-Origin": "http://localhost:3000"
      })
      .succeed(error.toString());
  }
}

async function register(data) {
  // Get user input
  const { fname, lname, email, password } = data;

  // Validate user input
  if (!(email && password && fname && lname)) {
    res.message = "All input is required";
    return res;
  }

  // check if user already exist
  // Validate if user exist in our database
  let oldUser = await axios.post('http://gateway.openfaas:8080/function/data-function',
    {
      table: "Users",
      record: { email },
      query: "findOne"
    }).then(function (response) {
      return response;
    }).catch(function (error) { });

  if (oldUser && oldUser.status == 200) {
    res.message = "User Already Exist. Please Login";
    res.status = 409;
    return res;
  }

  //Encrypt user password
  const encryptedPassword = await bcrypt.hash(password, 10);

  return axios.post('http://gateway.openfaas:8080/function/data-function', {
    table: "Users",
    record: {
      fname,
      lname,
      email: email.toLowerCase(), // sanitize: convert email to lowercase
      password: encryptedPassword,
    },
    query: "insertOne"
  }).then(response => {
    const user = response.data;
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.JWT_TOKEN_KEY,
      {
        expiresIn: "8h",
      }
    );
    // save user token
    user.password = null;
    user.token = token;
    // return new user
    res.status = 200;
    res.message = user;
    return res;
  })
    .catch(function (error) {
      res.status = 500;
      res.message = error.toString();
      return res;
    });
}

async function login(data) {
  // Get user input
  const { email, password } = data;
  // Validate user input
  if (!(email && password)) {
    res.message = "All input is required";
    return res;
  }
  // Validate if user exist in our database
  return await axios.post('http://gateway.openfaas:8080/function/data-function',
    {
      table: "Users",
      record: { email },
      query: "findOne"
    }).then(async function (requser) {
      let user = requser.data;

      if (requser.status == 200) {
        // Create token
        var correctPassword = await bcrypt.compare(password, user.password);
        if (correctPassword) {
          const token = jwt.sign(
            { user_id: user._id, email },
            process.env.JWT_TOKEN_KEY,
            {
              expiresIn: "8h",
            }
          );
          // save user token
          user.token = token;
          user.password = null;
          res.status = 200;
          res.message = user;
          return res;
        }
      }
      res.status = 404;
      res.message = "Invalid Credentials";
      return res;
    }).catch(function (error) {
      res.status = 404;
      res.message = "Invalid Credentials";
      return res;
    });
}
