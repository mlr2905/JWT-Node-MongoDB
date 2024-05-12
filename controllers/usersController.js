const User = require("../models/User");
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// פונקציה לשליחת אימייל
function sendEmail(to, subject, text) {
    // הגדרת הגישה לחשבון ה-Gmail שלך
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'skyrocket.ask@gmail.com',
            pass: 'Miki260623' // אני ממליץ להשתמש בסיסמה יציבה או להשתמש באפליקציית סיסומי אפיקי של גוגל (App Passwords) אם כן הגדרת כך בחשבון הגוגל שלך.
        }
    });

    // הגדרת האימייל שישלח
    const mailOptions = {
        from: 'skyrocket.ask@gmail.com',
        to: to,
        subject: subject,
        text: text
    };

    // שליחת האימייל
    transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

// handle errors
const handleErrors = (err) => {
  console.log(err.message, err.code);
  let errors = { email: '', password: '' };

  // incorrect email
  if (err.message === 'incorrect email') {
    errors.email = 'That email is not registered';
  }

  // incorrect password
  if (err.message === 'incorrect password') {
    errors.password = 'That password is incorrect';
  }

  // duplicate email error
  if (err.code === 11000) {
    errors.email = 'that email is already registered';
    return errors;
  }

  // validation errors
  if (err.message.includes('user validation failed')) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message;
    });
  }
  return errors;
}



// create json web token
const maxAge = 3 * 24 * 60 * 60;
const createToken = (id, email) => {
  return jwt.sign({ id, email}, 'secret key', {
    expiresIn: maxAge
  });
};

module.exports.signup_post = async (request, response) => {
  const { email, password } = request.body;
  const username = email.substring(0, email.indexOf('@'));


  try {
    console.log('mongo email, password', email, password);
    const user = await User.create({ email, password });
    console.log('mongo תשובה', user);
    // const token = createToken(user._id, email);
    // response.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 });
    const a = { username: username, email: email, mongo_id: user._id.toString() }
    console.log('תשובה שנשלחה לשרת ממנוגו', a);
    sendEmail(`${email}`, 'The list was made successfully', 'Welcome to the site, this is your password, please save it: ;'`${password}`);

    response.status(201).json({ username: username, email: email, mongo_id: user._id.toString() });
  }
  catch (err) {
    const errors = handleErrors(err);
    response.status(400).json({ errors });
  }
}

module.exports.login_post = async (req, res) => {
  try {
    let errors = { email: '', password: '' };

    const searchQuery = req.body;
    console.log(searchQuery);
    // Check if searching by password
    if (searchQuery.password) {
      const password = searchQuery.password;
      const cipher = crypto.createCipher('aes-256-cbc', 'ml7585474rl');
      let encryptedPassword = cipher.update(password, 'utf8', 'hex');
      encryptedPassword += cipher.final('hex');
      searchQuery.password = encryptedPassword;
    }
    const user = await User.findOne({ email: searchQuery.email });
    console.log('user', user);
    if (user === null) {
      errors.email = 'That email is not registered';
      console.log(errors);

      return   res.status(200).json({errors});

    } else {
          if (searchQuery.password !== user.password) {
        errors.password = 'Wrong password try again';
        res.status(200).json({errors})      } else {
        console.log("התחברות מוצלחת");

        const id = user._id.toString()
        const token = createToken(id, user.email);
        res.status(200).json({ jwt: token });
      }
    }

  }
  catch (err) {
    res.cookie('jwt', '', { maxAge: 1 });
    const errors = handleErrors(err);
    res.status(400).json({ errors });
  }
}

module.exports.logout_get = (req, res) => {
  res.cookie('jwt', '', { maxAge: 1 });
  res.status(200).json({ status: "logged out" });
}

module.exports.validate_token = (req, res) => {
  console.log(req.body);
  const token = req.body.token; // Assuming the token is sent in the body of the request
  console.log('token', token);

  if (!token) {
    console.log('401');
    res.status(401).json({ "status": "no jwt present" })
    return;
  }
  console.log(token);
  jwt.verify(token, 'secret key', async (err, decodedToken) => {
    if (err) {
      console.log('402');
      res.status(401).json({ "status": "token not valid!" })
      return;
    } else {
      // valid token
      // check if this user is still in the db
      let user = await User.findById(decodedToken.id);
      console.log('200');
      res.status(200).json({ valid: "token valid" });
      return;
    }
  });
  //   res.status(401).json({"status": "token not valid!"})
  //   return;
}

module.exports.search_users = async (req, res) => {
  try {
    const searchQuery = req.query;

    // Check if searching by password
    if (searchQuery.password) {
      const password = searchQuery.password;
      const cipher = crypto.createCipher('aes-256-cbc', 'ml7585474rl');
      let encryptedPassword = cipher.update(password, 'utf8', 'hex');
      encryptedPassword += cipher.final('hex');
      searchQuery.password = encryptedPassword;
    }

    const users = await User.find(searchQuery);
    if (users[0]) {
      res.status(200).json(users[0]); // Assuming you only want the first user
    } else {
      const searchCriteria = Object.entries(searchQuery)
        .filter(([key, value]) => value != null) // Filter out nullish values
        .map(([key, value]) => `${key}:${value}`); // Build criteria strings
      const criteriaString = searchCriteria.join(', ');

      res.status(404).json({ status: `No users matching the criteria were found: ${criteriaString}` });
    }

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports.decryptPassword = async (req, res) => {
  const encryptedPassword = req.query.password
  console.log('encryptedPassword', encryptedPassword);
  try {
    const decipher = crypto.createDecipher('aes-256-cbc', 'ml7585474rl');
    let decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8');
    decryptedPassword += decipher.final('utf8');
    res.status(200).json({ Succeeded: `This is your password: || ${decryptedPassword} ||` });

  } catch (err) {
    res.status(404).json({ err: `'FALSE POSITIVE TEST': || ${encryptedPassword} ||` });
  }
};
