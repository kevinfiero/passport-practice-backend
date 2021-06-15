var mongoose = require('mongoose');
var express = require('express');
var cors = require('cors');
var passport = require('passport');
var passportLocal = require('passport-Local');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var bcrypt = require('bcryptjs');
require('dotenv').config();
var User = require('./User')

const LocalStrategy = passportLocal.Strategy;

mongoose.connect(process.env.MONGO_CONNECTION, {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true
}, function (err) {
  if (err) throw err;
  console.log("Connected")
});

// Passport Middleware
const app = express();
app.use(express.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }))
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

//Administrator Middleware

const isAdministratorMiddleware = (req, res, next) => {
  const { user } = req;
  if (user) {
    User.findOne({username: user.username}, (err, doc) => {
      if (err) throw err;
      if (doc?.isAdmin) {
        next();
      }
      else{
        res.send("Sorry, only administrators can perform this operation");
      }
    })
  }
  else {
    res.send("Sorry, you are not logged in");
  }

}

//Passport
passport.use(new LocalStrategy((username, password, done) => {
  User.findOne({ username: username }, (err, user) => {
    if (err) throw err;
    if (!user) return done(null, false);
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) throw err;
      if (result === true) {
        return done(null, user);
      } else {
        return done(null, false);
      }
    });
  });
})
);

passport.serializeUser((user, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id, cb) => {
  User.findOne({ _id: id }, (err, user) => {
    const userInformation = {
      username: user.username,
      isAdmin: user.isAdmin,
      id: user._id
    };
    cb(err, userInformation);
  });
});


//Routes
app.post('/register', async (req, res) => {

  const { username, password } = req?.body;

  if (!username || !password || typeof username !== "string" || typeof password !== "string") {
    res.send("Improper Values");
    return;
  }

  User.findOne({ username }, async (err, doc) => {
    if (err) throw err;
    if (doc) res.send("User Already Exists");
    if (!doc) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        username,
        password: hashedPassword,
        isAdmin: false
      })
      await newUser.save();
      res.send("success");
    }
  })
})

app.post("/login", passport.authenticate("local"), (req, res) => {
  res.send("success");
});

app.get("/user", (req, res) => {
  res.send(req.user);
});

app.get("/getallusers", isAdministratorMiddleware, async (req, res) => {
  await User.find({}, (err, data) => {
    if (err) throw err; 
    const filteredUsers = [];
    data.forEach((item) => {
      userInformation = {      
        id: item._id,
        username: item.username,
        isAdmin: item.isAdmin
      }
      filteredUsers.push(userInformation);
    })
    res.send(filteredUsers);
  })
});

app.get("/logout", (req, res) => {
  req.logout();
  res.send("success");
});

app.post("/deleteuser", isAdministratorMiddleware, async(req, res) => {
  const { id } = req.body;
  await User.findByIdAndDelete(id, err => {
    if (err) throw err;
    res.send("success");
  })
});

app.listen(4000, () => {
  console.log("Server Started")
});
