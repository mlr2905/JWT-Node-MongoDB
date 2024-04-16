
const express = require('express');
const mongoose = require('mongoose');
const usersRouter = require('./routers/usersRouter');
const config = require('config')

const app = express(); 

// middleware
app.use(express.static('public'));
app.use(express.json());

// view engine
app.set('view engine', 'ejs');

// mongodb://root:rootpassword@localhost:27022/user-demo?authSource=admin
const dbURI = `mongodb://${config.mongodb.user}:${config.mongodb.password}@` +
        `${config.mongodb.host}:${config.mongodb.port}/user-demo?authSource=${config.mongodb.authSource}`;
//const dbURI = `mongodb://${config.mongodb.user}:${config.mongodb.password}@${config.mongodb.host}:${config.mongodb.port}/user-demo?authSource=${config.mongodb.authSource}`;

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true})
  .then((result) => {
    console.log('Mongo connected ...');
    console.log(result.connection._connectionString)    
    app.listen(3001, () => console.log(`Listening to port ${3001}`))
  })
  .catch((err) => console.log(err));

  app.use('/api/users/', usersRouter);