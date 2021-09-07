'use strict'

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
let res = { status: 400, message: "error occured" };

module.exports = async (event, context) => {
  const action = event.body.action;
  const data = event.body.data;
  let ret;
  console.log(event.body);

  if (action == "login")
    ret = await login(data);
  else
    ret = await register(data);

  return context
    .status(ret.status)
    .headers({
      "Content-type": "application/json; charset=utf-8"
    })
    .succeed(ret.message);

}

async function register(data) {
  //try {
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
    console.log(user);

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
  //try {
  // Get user input
  const { email, password } = data;
  // Validate user input
  if (!(email && password)) {
    res.message = "All input is required";
    return res;
  }
  // Validate if user exist in our database
  axios.post('http://gateway.openfaas:8080/function/data-function',
    {
      table: "Users",
      record: { email },
      query: "findOne"
    }).then(function (requser) {
      const user = requser.data;

      if (requser.status == 200 && (await bcrypt.compare(password, user.password))) {
        // Create token
        const token = jwt.sign(
          { user_id: user._id, email },
          process.env.JWT_TOKEN_KEY,
          {
            expiresIn: "8h",
          }
        );

        // save user token
        user.token = token;
        user.password = "";
        res.status = 200;
        res.message = user;
        return res;
      }
    }).catch(function (error) {
      res.status = 404;
      res.message = "Invalid Credentials";
      return res;
    });
}
