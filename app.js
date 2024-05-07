
const express = require('express');
const mongoose = require('mongoose');
mongoose.set('strictQuery', true);

const usersRouter = require('./routers/usersRouter');

const app = express(); 

// middleware
app.use(express.static('public'));
app.use(express.json());

// app.get('*', async (req, res, next) => {
//   const clientIP = req.ip;
//   console.log('Client IP:', clientIP);
//   next()
//   // המשך עיבוד הבקשה כרגיל
// });
// app.post('*', async (req, res, next) => {
//   const allowedIP = '216.24.57.4'; // כתובת ה-IP שמורשת
//   const clientIP = req.ip;

//   if (clientIP !== allowedIP) {
//       return res.status(403).send("Access denied");
//   }

//   console.log('Client IP:', clientIP);
//   next();
//   // המשך עיבוד הבקשה כרגיל
// });

// view engine
app.set('view engine', 'ejs');

const dbURI ="mongodb+srv://7585474:Nyfo91h1uBFBzcaW@mongomr.47dajov.mongodb.net/mongoT3?retryWrites=true&w=majority";
;
//const dbURI = `mongodb://${config.mongodb.user}:${config.mongodb.password}@${config.mongodb.host}:${config.mongodb.port}/user-demo?authSource=${config.mongodb.authSource}`;

mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true})
  .then((result) => {
    console.log('Mongo connected ...');
    console.log(result.connection._connectionString)    
    app.listen(3001, () => console.log(`Listening to port ${3001}`))
  })
  .catch((err) => console.log(err));

  app.use('', usersRouter);

