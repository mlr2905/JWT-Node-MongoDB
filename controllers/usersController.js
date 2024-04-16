const User = require("../models/User");

module.exports.post = async (request, response) => {
    const { email, password } = request.body;
    
  
    try {
      const user = await User.create({ email, password });
      response.status(201).json({ user_id: user._id });
    }
    catch(err) {
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

    // Check if searching by ID
      // Convert _id to ObjectId only if searching by 

    // Perform user search based on searchQuery
    const users = await User.find(searchQuery);

    if (users[0].id_pg > 0) {

      res.status(200).json(users[0]);
    } else {
      res.status(404).json({ status: "לא נמצאו משתמשים התואמים לקריטריון" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

  
  
  // module.exports.search_user = async (req, res) => {
  //   try {
  //     const user = await User.findById(req.params.id, { _id,id_pg, username, email }); // ציין את השדות הרצויים
  //     if (user) {
  //       res.status(200).json(user);
  //     } else {
  //       res.status(404).json({ status: "User not found" });
  //     }
  //   } catch (err) {
  //     res.status(500).json({ error: err.message });
  //   }
  // };


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