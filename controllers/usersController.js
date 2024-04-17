const User = require("../models/User");
const crypto = require('crypto');

module.exports.post = async (request, response) => {
  const { email, password } = request.body;
  try {
    const user = await User.create({ email, password });
    response.status(201).json({ user_id: user._id });
  }
  catch (err) {
    const errors = handleErrors(err);
    response.status(400).json({ errors });
  }
}

module.exports.get_by_id = async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user) {
      res.status(200).json(user);
    } else {
      res.status(404).json({ status: "User not found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};



module.exports.search_users = async (req, res) => {
  try {
    const searchQuery = req.query;

    // Check if searching by password
    if (searchQuery.password) {
      const password = searchQuery.password;
      const cipher = crypto.createCipher('aes-256-cbc', 'mySecretKey');
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




module.exports.encrypt_and_update_all_passwords = async (req, res) => {
  try {
    // מביא את כל המשתמשים מהמסד נתונים
    const users = await User.find();
    
    // מעביר על כל המשתמשים ומצפה את הסיסמאות שלהם
    await Promise.all(users.map(async (user) => {
      const password = user.password;
      // משתמש ב-AES להצפנת הסיסמה
      const cipher = crypto.createCipher('aes-256-cbc', 'mySecretKey');
      let encryptedPassword = cipher.update(password, 'utf8', 'hex');
      encryptedPassword += cipher.final('hex');
      // מעדכן את הסיסמה של המשתמש להיות הסיסמה המוצפנת
      user.password = encryptedPassword;
      // שומר את השינויים במסד הנתונים
      await user.save();
    }));
    
    // מחזיר הודעת תגובה כאשר כל הסיסמאות עודכנו בהצלחה
    res.status(200).json({ message: "Passwords encrypted and updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};



module.exports.delete = async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    if (deletedUser) {
      res.status(200).json({ status: "User deleted" });
    } else {
      res.status(404).json({ status: "User not found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
module.exports.deleteAll = async (req, res) => {
  try {
    await User.deleteMany({});
    res.status(200).json({ status: "All users deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};






