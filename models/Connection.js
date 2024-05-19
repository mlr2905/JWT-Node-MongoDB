const mongoose = require('mongoose');

const connectionSchema = new mongoose.Schema({
  email: String ,
  ipAddress: String
});



const Connection = mongoose.model('Connections', connectionSchema);

module.exports =Connection;