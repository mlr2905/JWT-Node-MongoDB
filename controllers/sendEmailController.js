const nodemailer = require('nodemailer');

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
// פונקציה גנרית לשליחת מיילים עם תבניות מובנות
async function sendEmail(type, email, data = {}) {
  let subject, html;

  switch (type) {
    case 'verification_code':
      subject = 'Verification Code - Skyrocket';
      html = createVerificationCodeTemplate(data.code);
      break;

    case 'new_device_alert':
      subject = 'New device sign-in detected - Skyrocket';
      html = createNewDeviceAlertTemplate(email, data.ip, data.userAgent);
      break;

    case 'credential_registered':
      subject = 'New Access Key Added - Skyrocket';
      html = createCredentialRegisteredTemplate(email, data.deviceName, data.totalCredentials);
      break;

    case 'user_registered':
      subject = 'Welcome to Skyrocket - Account Created Successfully';
      html = createUserRegisteredTemplate(email, data.name, data.password);
      break;

    case 'login_from_new_device':
      subject = 'New device sign-in detected - Skyrocket';
      html = createLoginFromNewDeviceTemplate(email, data.ip, data.userAgent, data.timestamp);
      break;

    case 'password_reset':
      subject = 'Password Reset Request - Skyrocket';
      html = createPasswordResetTemplate(email, data.resetLink, data.expiresIn);
      break;

    case 'login_success':
      subject = 'Successful Login - Skyrocket';
      html = createLoginSuccessTemplate(email, data.ip, data.userAgent, data.timestamp);
      break;

    case 'custom':
      subject = data.subject;
      html = data.html;
      break;

    default:
      throw new Error(`Unknown email type: ${type}`);
  }

  const mailOptions = {
    from: 'skyrocket.ask@gmail.com',
    to: email,
    subject: subject,
    html: html
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`${type} email sent successfully to: ${email}`);
    return { success: true, type };
  } catch (error) {
    console.error(`Failed to send ${type} email to ${email}:`, error);
    return { success: false, error, type };
  }
}

// תבניות המיילים
function createVerificationCodeTemplate(code) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Verification Code</h2>
      <p>Your verification code is:</p>
      <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
        <h1 style="color: #28a745; font-size: 36px; margin: 0; letter-spacing: 5px;">${code}</h1>
      </div>
      <p style="color: #666;">This code will expire in 5 minutes.</p>
      <hr>
      <p>Best regards,<br>The Skyrocket Team</p>
    </div>
  `;
}

function createNewDeviceAlertTemplate(email, ip, userAgent) {
  const timestamp = new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '') + ' GMT';
  
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #dc3545;">🚨 New Sign-in Alert</h2>
      <p>We detected a new sign-in to your account using an access key:</p>
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <ul style="margin: 0; padding-left: 20px;">
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Time:</strong> ${timestamp}</li>
          <li><strong>IP Address:</strong> ${ip}</li>
          <li><strong>Device:</strong> ${userAgent}</li>
          <li><strong>Method:</strong> Access Key (WebAuthn)</li>
        </ul>
      </div>
      
      <p>✅ If this was you, you can safely ignore this message.</p>
      <p>⚠️ If you don't recognize this sign-in, please secure your account immediately by removing any unauthorized access keys from your account settings.</p>
      
      <hr>
      <p>Best regards,<br>The Skyrocket Team</p>
    </div>
  `;
}

function createCredentialRegisteredTemplate(email, deviceName, totalCredentials) {
  const timestamp = new Date().toLocaleString('en-US', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZoneName: 'short'
  });

  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #28a745;">🔑 Access Key Successfully Added</h2>
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
      <p>Best regards,<br>The Skyrocket Team</p>
      
      <p style="font-size: 12px; color: #666;">
        You can manage your access keys from your account settings page.
      </p>
    </div>
  `;
}

function createUserRegisteredTemplate(email, name, password) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #28a745;">🎉 Welcome to Skyrocket!</h2>
      <p>We are delighted you chose to sign up for our website!</p>
      <p>We look forward to seeing you soon and providing you access to all our exciting services and content.</p>
      
      <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
        <h3 style="margin-top: 0;">Account Details:</h3>
        <ul style="margin: 0; padding-left: 20px;">
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Registration Date:</strong> ${new Date().toLocaleDateString()}</li>
          ${password ? `<li><strong>Password:</strong> <code style="background-color: #e9ecef; padding: 2px 4px; border-radius: 3px;">${password}</code></li>` : ''}
        </ul>
      </div>
      
      ${password ? '<p style="color: #dc3545;"><strong>⚠️ Important:</strong> Please keep your password safe and don\'t forget to check the homepage for updates!</p>' : ''}
      
      <h3>Getting Started</h3>
      <p>Here are some things you can do with your new account:</p>
      <ul>
        <li>Set up Access Keys for secure passwordless login</li>
        <li>Explore our features and services</li>
        <li>Customize your account settings</li>
      </ul>
      
      <p style="margin: 20px 0;">
        <a href="https://skyrocket.onrender.com/login.html?email=${email}" 
           style="background-color: #007bff; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          Login to Your Account
        </a>
      </p>
      
      <hr>
      <p>Best regards,<br>The Skyrocket Team</p>
      
      <p style="font-size: 12px; color: #666;">
        If you didn't create this account, please contact our support team immediately.
      </p>
    </div>
  `;
}

function createLoginFromNewDeviceTemplate(email, ip, userAgent, timestamp) {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #ffc107;">🔐 New Device Sign-in Alert</h2>
      <p>We're verifying a recent sign-in for <strong>${email}</strong>:</p>
      
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <ul style="margin: 0; padding-left: 20px;">
          <li><strong>Timestamp:</strong> ${timestamp}</li>
          <li><strong>IP Address:</strong> ${ip}</li>
          <li><strong>User Agent:</strong> ${userAgent}</li>
        </ul>
      </div>
      
      <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
        <p style="margin: 0;"><strong>⚠️ Security Notice:</strong> You're receiving this message because of a successful sign-in from a device that we didn't recognize.</p>
      </div>
      
      <p><strong>If you believe that this sign-in is suspicious:</strong></p>
      <ol>
        <li>Reset your password immediately</li>
        <li>Review your account for any unauthorized changes</li>
        <li>Contact our support team</li>
      </ol>
      
      <p><strong>If you're aware of this sign-in:</strong> Please disregard this notice. This can happen when you use your browser's incognito or private browsing mode or clear your cookies.</p>
      
      <hr>
      <p>Thanks,<br>
      Best regards,<br>
      The Skyrocket Team</p>
    </div>
  `;
}

function createPasswordResetTemplate(email, resetLink, expiresIn = '1 hour') {
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #dc3545;">🔒 Password Reset Request</h2>
      <p>We received a request to reset your password for your Skyrocket account.</p>
      
      <div style="background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107;">
        <p style="margin: 0;"><strong>⚠️ Important:</strong> This link will expire in ${expiresIn}.</p>
      </div>
      
      <p style="margin: 20px 0;">
        <a href="${resetLink}" 
           style="background-color: #dc3545; color: white; padding: 12px 24px; 
                  text-decoration: none; border-radius: 5px; display: inline-block;">
          Reset Your Password
        </a>
      </p>
      
      <p>If you didn't request this password reset, you can safely ignore this email. Your password will remain unchanged.</p>
      
      <p>If the button doesn't work, copy and paste this link into your browser:</p>
      <p style="word-break: break-all; color: #666;">${resetLink}</p>
      
      <hr>
      <p>Best regards,<br>The Skyrocket Team</p>
    </div>
  `;
}

function createLoginSuccessTemplate(email, ip, userAgent, timestamp) {
  const time = timestamp || new Date().toISOString().replace(/T/, ' ').replace(/\..+/, '') + ' GMT';
  
  return `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #28a745;">✅ Successful Login</h2>
      <p>You have successfully logged into your Skyrocket account.</p>
      
      <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
        <h3 style="margin-top: 0;">Login Details:</h3>
        <ul style="margin: 0; padding-left: 20px;">
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Time:</strong> ${time}</li>
          <li><strong>IP Address:</strong> ${ip}</li>
          <li><strong>Device:</strong> ${userAgent}</li>
        </ul>
      </div>
      
      <p>If this wasn't you, please secure your account immediately and contact our support team.</p>
      
      <hr>
      <p>Best regards,<br>The Skyrocket Team</p>
    </div>
  `;
}

module.exports = {
  sendEmail
}