const User = require("../models/User");

module.exports.post = async (request, response) => {
    const { email, password } = request.body;
    //email = "itayhau@gmail.com"
    //password = "123456"
  
    try {
      const user = await User.create({ email, password });
      response.status(201).json({ user_id: user.id_pg });
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