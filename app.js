
const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

mongoose.set('strictQuery', true);

const usersRouter = require('./routers/usersRouter');

const app = express(); 

// middleware
app.use(express.static('public'));
app.use(express.json());


// view engine
app.set('view engine', 'ejs');

//const dbURI = `mongodb://${config.mongodb.user}:${config.mongodb.password}@${config.mongodb.host}:${config.mongodb.port}/user-demo?authSource=${config.mongodb.authSource}`;

mongoose.connect(process.env.DBURI, { useNewUrlParser: true, useUnifiedTopology: true})
  .then((result) => {
    console.log('Mongo connected ...');
    console.log(result.connection._connectionString)    

    app.listen(3001, () => console.log(`Listening to port ${3001}`))
    console.log('Express server is running ....')    

  })
  .catch((err) => console.log(err));

  app.use('', usersRouter);

