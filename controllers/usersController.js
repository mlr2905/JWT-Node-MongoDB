const User = require("../models/User");
const crypto = require('crypto');
const jsonwebtoken = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: 'skyrocket.ask@gmail.com',
    pass: 'akvrvcwrdtaoeyow'
  },
  tls: {
    rejectUnauthorized: false
  }

});



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
  return jsonwebtoken.sign({ id, email }, 'secret key', {
    expiresIn: maxAge
  });
};
let temporaryVerificationCodes = {}; // מבנה נתונים לשמירת קודי האימות הזמניים לכל משתמש

// פונקציה ליצירת קוד אימות של 6 ספרות
function generateOTP() {
  let otp = '';
  for (let i = 0; i < 6; i++) {
    otp += Math.floor(Math.random() * 10); // הוספת ספרה אקראית
  }
  return otp;
}


module.exports.authcode = async (request, response) => {
  const email = request.body.email
  console.log("email", email);
  try {
    if (temporaryVerificationCodes.hasOwnProperty(email)) {
      delete temporaryVerificationCodes[email];
    }
    const verificationCode = generateOTP();
    // שמירת קוד האימות במבנה הנתונים
    temporaryVerificationCodes[email] = verificationCode;
    console.log(temporaryVerificationCodes);
    const mailOptions = {
      from: 'skyrocket.ask@gmail.com',
      to: email,
      subject: 'verification code',
      html: `
        <p>Your verification code is: ${verificationCode}</p>
        </br>
        <p>Best regards,</p>
        <p>The Skyrocket Team</p>
        `
    };
    console.log(mailOptions);
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error)
        return response.status(404).json({"e":"yes", "error": error });

      } else {
        setTimeout(() => {
          delete temporaryVerificationCodes[email];
          console.log(`The verification code for ${email} has been deleted.`);
        }, 5 * 60 * 1000); // זמן במילישניות - 5 דקות

         response.status(201).json({"e":"no", "code": "succeeded" });
      }
    });

  }
  catch (err) {
     return response.status(400).json({"e":"yes" ,"error": err });
  }
}

module.exports.verifyCode = async (request, response) => {
  let errors = { email: '', password: '' };

  const email = request.body.email
  const inputCode = request.body.code
  try {
    // פונקציה לאימות ומחיקת קוד האימות
    if (temporaryVerificationCodes.hasOwnProperty(email)) {
      const storedCode = temporaryVerificationCodes[email];

      if (inputCode === storedCode) {

        const user = await User.findOne({ email: email });
        if (user === null) {
          errors.email = 'That email is not registered';
          return response.status(404).json({ errors });

        } else {

          console.log("data", user);
          const id = user._id.toString()
          const token = createToken(id, user.email);
          console.log("token", token);
          console.log('The code is correct!');
          delete temporaryVerificationCodes[email];
          console.log({ "token": token, "code": "The code is correct!" });
          return  response.status(200).json({ "e":"no","token": token, "code": "The code is correct!" });
        
        }
      } else {
        console.log('The code is incorrect. Try again.');

       return response.status(404).json({ "errors": "The code is incorrect. Try again." });
      }
    } else {
      console.log({ "error": 'No verification code found for the email entered.' });
      return response.status(404).json({ "errors": 'No verification code found for the email entered.' });

    }

  } catch (err) {
   return response.status(400).json({ "error": err });
  }

}
module.exports.signup_post = async (request, response) => {
  const searchQuery = request.body;
  const email = searchQuery.email
  const cipher = crypto.createCipher('aes-256-cbc', 'ml7585474rl');
  let encryptedPassword = cipher.update(searchQuery.password, 'utf8', 'hex');
  encryptedPassword += cipher.final('hex');
  const password = encryptedPassword;
  const username = email.substring(0, email.indexOf('@'));
  try {
    console.log('mongo email, password', email, password);
    const user = await User.create({ email, password });

    // הגדרת הגישה לחשבון ה-Gmail שלך


    // הגדרת האימייל שישלח
    const mailOptions = {
      from: 'skyrocket.ask@gmail.com',
      to: email,
      subject: 'Successful registration - welcome to our website',
      html:
        `
        <p>We are delighted you chose to sign up for our website!</p>
        <p>We look forward to seeing you soon and providing you access to all our exciting services and content.</p>
        <p>Please keep your password: <b>${searchQuery.password}</b> safe and don't forget to check the homepage for updates!</p>
        <p><a href="https://skyrocket.onrender.com/login.html?email=${email}" style="color: blue; padding: 10px 20px; text-decoration: none; border-radius: 5px; background-color: transparent; border: 2px solid blue;">Login</a></p>
        </br>
        <p>Best regards,</p>
        <p>The Skyrocket Team</p>
        
         `
    };

    // שליחת האימייל
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
        return response.status(404).json({error});

      } else {
        console.log('Email sent: ' + info.response);
        return response.status(201).json({ username: username, email: email, mongo_id: user._id.toString() });

      }
    });

  }
  catch (err) {
    const errors = handleErrors(err);
   return response.status(400).json({ errors });
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

      return res.status(200).json({ errors });

    } else {
      if (searchQuery.password !== user.password) {
        errors.password = 'Wrong password try again';
        res.status(200).json({ errors })
      } else {
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
  jsonwebtoken.verify(token, 'secret key', async (err, decodedToken) => {
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
