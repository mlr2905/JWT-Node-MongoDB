const mongoose = require('mongoose');

const connectionSchema = new mongoose.Schema({
  email: String ,
  timestamp: String,
  ipAddress: String,
  userAgent: String
});

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  connections: [connectionSchema] // שדה נוסף לרשימת החיבורים
});

const Connections = mongoose.model('Connections', userSchema);

module.exports =Connections;