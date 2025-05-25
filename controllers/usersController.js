const User = require("../models/User");
const Connection = require("../models/Connection");
const WebAuthnCredential = require('../models/WebAuthn');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { log } = require("util");

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.USER,
    pass: process.env.PASS
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
  return jwt.sign({ id, email }, 'secret key', {
    expiresIn: maxAge
  });
};
let code_storage = {}; // מבנה נתונים לשמירת קודי האימות הזמניים לכל משתמש

// פונקציה ליצירת קוד אימות של 6 ספרות
function generateOTP() {
  let otp = '';
  for (let i = 0; i < 6; i++) {
    otp += Math.floor(Math.random() * 10); // הוספת ספרה אקראית
  }
  return otp;
}


module.exports.registerCredential = async (request, response) => {
  const { email, credentialID, publicKey, credentialName } = request.body;

  try {
    // Validation
    if (!email || !credentialID || !publicKey) {
      return response.status(400).json({ 
        e: 'yes', 
        error: 'Missing required fields: email, credentialID, and publicKey' 
      });
    }

    // חיפוש המשתמש
    const user = await User.findOne({ email });
    if (!user) {
      return response.status(404).json({ 
        e: 'yes', 
        error: 'User not found' 
      });
    }

    // בדיקה אם כבר קיים credential עם אותו ID
    const existingCredential = await WebAuthnCredential.findOne({ credentialID });
    if (existingCredential) {
      return response.status(409).json({ 
        e: 'yes', 
        error: 'Credential already exists' 
      });
    }

    // יצירת שם אוטומטי ל-credential אם לא סופק
    const deviceName = credentialName || `Access Key ${new Date().toLocaleDateString()}`;

    // שמירת ה-credential החדש
    const newCredential = new WebAuthnCredential({
      user: user._id,
      credentialID,
      publicKey,
      counter: 0,
      deviceName: deviceName,
      createdAt: new Date(),
      lastUsed: null
    });

    await newCredential.save();

    // ספירת מספר ה-credentials של המשתמש
    const credentialCount = await WebAuthnCredential.countDocuments({ user: user._id });

    // שליחת אימייל התראה על הוספת Access Key חדש
    await sendCredentialRegisteredEmail(email, deviceName, credentialCount);

    return response.status(201).json({ 
      e: 'no', 
      code: 'credential_registered',
      message: 'Access key registered successfully',
      credential: {
        id: newCredential._id,
        deviceName: deviceName,
        createdAt: newCredential.createdAt
      }
    });

  } catch (err) {
    console.error('Credential registration error:', err);
    return response.status(500).json({ 
      e: 'yes', 
      error: 'Failed to register access key' 
    });
  }
};

module.exports.loginWithCredential = async (request, response) => {
  const { credentialID, signature, email, clientDataJSON, authenticatorData } = request.body;

  try {
    // Validation של הנתונים הנדרשים
    if (!credentialID || !signature || !email) {
      return response.status(400).json({ 
        e: 'yes', 
        error: 'Missing required fields: credentialID, signature, and email' 
      });
    }

    // חיפוש ה-credential במסד הנתונים
    const credential = await WebAuthnCredential.findOne({ credentialID }).populate('user');
    if (!credential) {
      return response.status(401).json({ 
        e: 'yes', 
        error: 'Credential not recognized' 
      });
    }

    // בדיקה שהאימייל תואם למשתמש
    if (credential.user.email !== email) {
      return response.status(401).json({ 
        e: 'yes', 
        error: 'Email does not match credential owner' 
      });
    }

  

    // עדכון זמן ההתחברות האחרון
    credential.lastUsed = new Date();
    await credential.save();

    // בדיקה אם זו התחברות מ-IP חדש
    const ip = request.ip || request.connection.remoteAddress || 'unknown';
    const userAgent = request.get('User-Agent') || 'unknown';
    
    const previousConnection = await Connection.findOne({ 
      email: email, 
      ipAddress: ip 
    });

    // יצירת JWT token
    const token = createToken(credential.user._id.toString(), credential.user.email);

    // אם זו התחברות מ-IP חדש, שלח התראה באימייל
    if (!previousConnection) {
      // שמירת ה-connection החדש
      const newConnection = new Connection({ 
        email: email, 
        ipAddress: ip,
        userAgent: userAgent,
        loginMethod: 'webauthn'
      });
      await newConnection.save();

      // שליחת אימייל התראה
      await sendNewDeviceAlert(email, ip, userAgent);
    }

    // החזרת תשובה מוצלחת
    return response.status(200).json({
      e: 'no',
      code: 'login_succeeded',
      jwt: token,
      user: {
        email: credential.user.email,
        id: credential.user._id,
        name: credential.user.name || credential.user.email
      }
    });

  } catch (err) {
    console.error('WebAuthn login error:', err);
    return response.status(500).json({ 
      e: 'yes', 
      error: 'Internal server error during authentication' 
    });
  }
};



// פונקציה לשליחת התראה על התחברות מהתקן חדש
async function sendNewDeviceAlert(email, ip, userAgent) {
  const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '') + ' GMT';
  
  const mailOptions = {
    from: 'skyrocket.ask@gmail.com',
    to: email,
    subject: 'New device sign-in detected - Skyrocket',
    html: `
      <h2>New Sign-in Alert</h2>
      <p>We detected a new sign-in to your account using an access key:</p>
      <ul>
        <li><strong>Email:</strong> ${email}</li>
        <li><strong>Time:</strong> ${timestamp}</li>
        <li><strong>IP Address:</strong> ${ip}</li>
        <li><strong>Device:</strong> ${userAgent}</li>
        <li><strong>Method:</strong> Access Key (WebAuthn)</li>
      </ul>
      
      <p>If this was you, you can safely ignore this message.</p>
      <p>If you don't recognize this sign-in, please secure your account immediately by removing any unauthorized access keys from your account settings.</p>
      
      <hr>
      <p>Best regards,<br>
      The Skyrocket Team</p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('New device alert sent to:', email);
  } catch (error) {
    console.error('Failed to send new device alert:', error);
    // לא נזרוק שגיאה כי זה לא אמור למנוע את ההתחברות
  }
}
async function sendCredentialRegisteredEmail(email, deviceName, totalCredentials) {
  const timestamp = new Date().toLocaleString('en-US', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });

  const mailOptions = {
    from: 'skyrocket.ask@gmail.com',
    to: email,
    subject: 'New Access Key Added - Skyrocket',
    html: `
      <h2>Access Key Successfully Added</h2>
      <p>A new access key has been registered to your Skyrocket account:</p>
      
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <ul style="margin: 0; padding-left: 20px;">
          <li><strong>Device Name:</strong> ${deviceName}</li>
          <li><strong>Date Added:</strong> ${timestamp}</li>
          <li><strong>Total Access Keys:</strong> ${totalCredentials}</li>
        </ul>
      </div>
      
      <h3>What are Access Keys?</h3>
      <p>Access Keys allow you to sign in securely without typing a password. You can use your device's built-in security features like fingerprint, face recognition, or security keys.</p>
      
      <h3>Security Notice</h3>
      <p>If you didn't add this access key, please:</p>
      <ol>
        <li>Log in to your account immediately</li>
        <li>Review and remove any unauthorized access keys</li>
        <li>Change your password</li>
        <li>Contact our support team</li>
      </ol>
      
      <p style="margin: 20px 0;">
        <a href="https://skyrocket.onrender.com/login.html?email=${email}" 
           style="background-color: #28a745; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          Login with Access Key
        </a>
      </p>
      
      <hr>
      <p>Best regards,<br>
      The Skyrocket Team</p>
      
      <p style="font-size: 12px; color: #666;">
        You can manage your access keys from your account settings page.
      </p>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('Credential registration email sent to:', email);
  } catch (error) {
    console.error('Failed to send credential registration email:', error);
  }
}
module.exports.authcode = async (request, response) => {
  const email = request.body.email
  console.log("email", email);
  try {
    if (code_storage.hasOwnProperty(email)) {
      delete code_storage[email];
    }
    const verificationCode = generateOTP();
    // שמירת קוד האימות במבנה הנתונים
    code_storage[email] = verificationCode;
    console.log(code_storage);
    const mailOptions = {
      from: 'skyrocket.ask@gmail.com',
      to: email,
      subject: 'verification code',
      html: `
        <p>Your verification code is: <b>${verificationCode}</b></p>
        </br>
        <p>Best regards,</p>
        <p>The Skyrocket Team</p>
        `
    };
    console.log(mailOptions);
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error)
        return response.status(404).json({ "e": "yes", "error": error });

      } else {
        setTimeout(() => {
          if (code_storage[email]) {
            delete code_storage[email];
            console.log(`The verification code for ${email} has been deleted.`);
          } else {
            console.log(`The verification code for ${email} was already deleted or does not exist.`);
          }
        }, 5 * 60 * 1000); // זמן במילישניות - 5 דקות

        response.status(201).json({ "e": "no", "code": "succeeded" });
      }
    });

  }
  catch (err) {
    return response.status(400).json({ "e": "yes", "error": err });
  }
}


module.exports.signup_post = async (request, response) => {
  const searchQuery = request.body;
  console.log(searchQuery)
  const email = searchQuery.email
  const authProvider = searchQuery.authProvider
  const iv = Buffer.from(process.env.IV, 'hex');
  const key = Buffer.from(process.env.KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encryptedPassword = cipher.update(searchQuery.password, 'utf8', 'hex');
  encryptedPassword += cipher.final('hex');
  const password = encryptedPassword;
  const username = email.substring(0, email.indexOf('@'));
  try {
    console.log('mongo email, password', email, password);
    const user = await User.create({ email, password ,authProvider});

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
        return response.status(404).json({ error });

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
    const email = searchQuery.email;
    const ip = searchQuery.ip;
    const userAgent = searchQuery.userAgent;
    console.log("abc", ip, userAgent);

    // Check if searching by password
    if (searchQuery.password) {
      const password = searchQuery.password;
      const iv = Buffer.from(process.env.IV, 'hex');
      const key = Buffer.from(process.env.KEY, 'hex');
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encryptedPassword = cipher.update(password, 'utf8', 'hex');
      encryptedPassword += cipher.final('hex');
      searchQuery.password = encryptedPassword;
    }

    // Find the user in the database
    const user = await User.findOne({ email: email });

    if (user === null) {
      errors.email = 'That email is not registered';
      return res.status(404).json({ errors });
    } else {
      if (searchQuery.password !== user.password) {
        console.log("Wrong password try again");

        errors.password = 'Wrong password try again';
        return res.status(400).json({ errors });
      } else {
        console.log("התחברות מוצלחת");

        // Check for previous Connection
        const previousConnection = await Connection.find({ "email": email, "ipAddress": ip });

        if (!previousConnection || previousConnection.length === 0) {
          const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '') + ' GMT';

          // Add a new connection record
          const newConnection = new Connection({ "email": email, "ipAddress": ip });
          await newConnection.save();

          const mailOptions = {
            from: 'skyrocket.ask@gmail.com',
            to: email,
            subject: 'Successful registration - welcome to our website',
            html:
              `
              <p>We're verifying a recent sign-in for ${email}:</p>
              <p>Timestamp:	${timestamp}</P>
              <p>IP Address:	${ip}</p>
              <p>User agent:	${userAgent}</p>
              <p>You're receiving this message because of a successful sign-in from a device that we didn’t recognize. If you believe that this sign-in is suspicious, please reset your password immediately.</p>
              <p>If you're aware of this sign-in, please disregard this notice. This can happen when you use your browser's incognito or private browsing mode or clear your cookies.</p>
              
              <p>Thanks,</p>
              </br>
              <p>Best regards,</p>
              <p>The Skyrocket Team</p>
               `
          };

          // שליחת האימייל
          transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
              console.log(error);
              return res.status(500).json({ error });
            } else {
              console.log('Email sent: ' + info.response);
              // Create token and return it to the user
              const id = user._id.toString();
              const token = createToken(id, user.email);
              return res.status(200).json({ jwt: token });
            }
          });
        } else {
          const id = user._id.toString();
          const token = createToken(id, user.email);
          return res.status(200).json({ jwt: token });
        }
      }
    }

  } catch (err) {
    return res.status(400).json({ "e":"yes","error": errors,err});
  }
}

module.exports.verifyCode = async (request, response) => {
  let errors = { email: '', password: '' };

  const email = request.body.email
  const inputCode = request.body.code
  try {
    // פונקציה לאימות ומחיקת קוד האימות
    if (code_storage.hasOwnProperty(email)) {
      const storedCode = code_storage[email];

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
          delete code_storage[email];
          console.log({ "token": token, "code": "The code is correct!" });
          return response.status(200).json({ "e": "no", jwt: token, "code": "The code is correct!" });

        }
      } else {
        console.log('The code is incorrect. Try again.');

        return response.status(404).json({ "e": "yes", "error": "The code is incorrect. Try again." });
      }
    } else {
      console.log('No verification code found for the email entered.');
      return response.status(404).json({ "e": "yes", "error": 'No verification code found for the email entered.' });

    }

  } catch (err) {
    return response.status(400).json({ "error": err });
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
      const iv = Buffer.from(process.env.IV, 'hex');
      const key = Buffer.from(process.env.KEY, 'hex');
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
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
  const encryptedPassword = req.query.password;
  console.log('encryptedPassword', encryptedPassword);
  try {
    const iv = Buffer.from(process.env.IV, 'hex');
    const key = Buffer.from(process.env.KEY, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv); 
    let decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf8');
    decryptedPassword += decipher.final('utf8');
    res.status(200).json({ Succeeded: `This is your password: || ${decryptedPassword} ||` });

  } catch (err) {
    res.status(404).json({ err: `'FALSE POSITIVE TEST': || ${encryptedPassword} ||` });
  }
};
