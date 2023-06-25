const express = require("express");

const app = express();
const { User } = require("./models");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const path = require("path");
const passport = require("passport"); 
const LocalStrategy = require("passport-local"); 
const session = require("express-session");
const connectEnsureLogin = require("connect-ensure-login");
const bcrypt = require("bcrypt");
const saltRounds = 10;


app.set("views", path.join(__dirname, "views"));

app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("some other secret string"));


app.use(express.static(path.join(__dirname, "Static")));
app.use(
  session({
    secret: "secret-key-that-no-one-can-guess",
    cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 24 hours
  })
);


app.use(passport.initialize());
app.use(passport.session());


passport.use(
  new LocalStrategy(
    {
      usernameField: "staffId",
      passwordField: "password",
    },
    (username, password, done) => {
      User.findOne({
        where: {
          staffId: username,
        },
      })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password" });
          }
        })
        .catch(() => {
          return done(null, false, { message: "User does not exists" });
        });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findByPk(id)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err, null);
    });
});

app.set("view engine", "ejs");



app.get("/signup", (request, response) => {
  response.render("signup");
});

app.get("/login", (request, response) => {
  response.render("login");
});

app.post(
  "/session",
  passport.authenticate("local", {
    failureRedirect: "/login",
  }),
  (request, response) => {
    response.redirect("/");
  }
);

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) return next(err);
    response.redirect("/login");
  });
});

app.get("/reset", connectEnsureLogin.ensureLoggedIn(), (req, res) => {
  res.render("reset", { user: req.user });
});

app.post("/reset", connectEnsureLogin.ensureLoggedIn(), async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.old_pass, saltRounds);
  const user = await User.findByPk(req.user.id);
  const result = await bcrypt.compare(req.body.old_pass, user.password);
  const new_hashedPassword = await bcrypt.hash(req.body.new_pass, saltRounds);
  if (result) {
    await user.update({
      password: new_hashedPassword,
    });
    res.redirect("/");
  } else {
    console.log("wrong password");
    res.redirect("/reset");
  }
});

app.get(
  "/",
  connectEnsureLogin.ensureLoggedIn(),
  async function (request, response) {
    const userId = request.user.id;
    const userAcc = await User.findByPk(userId);
    const userName = userAcc.name;
    if (request.accepts("html")) {
      response.render("index", {
        userName,
      });
    } else {
      response.json({
        userName,
        
      });
    }
  }
);


app.post("/users", async (request, response) => {
  
  const user = await User.findOne({
    where: {
      staffId: request.body.staffId,
    },
  });

if (user) {
  return response.redirect("/signup");
  }

  const hashedPassword = await bcrypt.hash(request.body.password, saltRounds);
  if (request.body.name == "") {
    return response.redirect("/signup");
  }
  if (request.body.staffId == "") {
    return response.redirect("/signup");
  }
  if (request.body.password.length < 6) {
    return response.redirect("/signup");
  }
  try {
    const user = await User.create({
      name: request.body.name,
      staffId: request.body.staffId,
      password: hashedPassword,
    });
    request.login(user, (err) => {
      if (err) {
        console.log(err);
      }
      response.redirect("/");
    });
  } catch (error) {
    request.flash("error", "Email already registered");
    return response.redirect("/signup");
  }
});

module.exports = app;
