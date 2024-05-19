const mongoose = require('mongoose');

const connectionSchema = new mongoose.Schema({
  email: String ,
  ipAddress: String
});



const Connections = mongoose.model('Connections', connectionSchema);

module.exports =Connections;