var express=require("express"),
    app=express(),
    mongoose=require("mongoose"),
    flash=require("connect-flash"),
    passport=require("passport"),
    bodyParser=require("body-parser"),
    nodemailer=require("nodemailer"),
    async=require("async"),
    crypto=require("crypto"),
    localStrategy   =require("passport-local"),
    passportLocalMongoose=require("passport-local-mongoose"),
    session=require("express-session"),
    MongoStore = require('connect-mongo')(session),
    methodOverride=require("method-override");
    
mongoose.connect("mongodb://localhost/todo_app");
app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(express.static(__dirname + "/public"));
app.use(methodOverride("_method"));
app.use(flash());


//==========database=======//
var userSchema=new mongoose.Schema({
   username:String,
   password:String,
   email:String,
   tasks:[{
       task:String
    }],
     resetPasswordToken:String,
    resetPasswordExpires:Date
});


userSchema.plugin(passportLocalMongoose);

var User=mongoose.model("User",userSchema);


//======passport configuration=========//
app.use(session({
    secret:"random words to generate hash code for password and store it as encrypted value",
    resave:false,
    saveUninitialized:false,
     store: new MongoStore({mongooseConnection:mongoose.connection,
         ttl:2*24*60*60
     })
}));
app.use(passport.initialize());
app.use(passport.session());
passport.use(new localStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//=============//

app.use(function(req,res,next){
    res.locals.currentUser=req.user;
    res.locals.error=req.flash("error");
    res.locals.success=req.flash("success");
    next();
});




//============routes================//

//home welcome page//
app.get("/",function(req,res){
    res.render("home");
});

//register page//
app.get("/register",function(req,res){
   res.render("register"); 
});

//register user//
app.post("/register",function(req,res){
   var newUser=new User({
       username:req.body.username,
       password:req.body.password,
       email:req.body.email
   });
   User.register(newUser,req.body.password,function(err,user){
        if(err){
             req.flash("error",err.message);
            return res.redirect("/register");
        }
        passport.authenticate("local")(req,res,function(){
             req.flash("success","Welcome to YelpCamp "+user.username);
            return res.redirect("/todo");
        });
    });
});
    
//login page//
app.get("/login",function(req,res){
    res.render("login");
});

app.post("/login",passport.authenticate("local",{
    successRedirect:"/todo",
    failureRedirect:"/login",
    failureFlash: true,
    successFlash: 'Welcome to TODO App!'
}),function(req,res){
});

app.get("/todo",function(req, res) {
   res.render("todo"); 
});

app.get("/todo/new",function(req, res) {
    res.render("newtask");
});

app.post("/:id/todo/new",function(req,res){
    //
   User.findById(req.params.id, function(err,user){
       if(err){
             req.flash("error","User not found");
          return res.redirect("/todo");
       }else{
           user.tasks.push({
               task: req.body.task
               
           });
           user.save(function(err,done){
              if(err) {
                    req.flash("error","error");
               return console.log(err);
              }else{
                   req.flash("success","Task added");
                  res.redirect("/todo");
              }
           });
       }
   });
});

app.patch("/todo/:id",function(req,res){
  User
    .findById(req.user.id, function(err, foundUser) {
        if(err){
            req.flash("error",err.message);
            console.log(err);
            return res.redirect("back");
        } if(!foundUser) {
              req.flash("error","User not found");
            return res.redirect("back");
        } else {
            foundUser.update({$pull: {tasks: {_id: req.params.id}}}, function(err) {
                if(err) {
                    req.flash("error",err.message);
                    console.log(err);
                    return res.redirect("back");
                } else {
                      req.flash("success","Task removed");
                    return res.redirect("/todo");
                }
            });
        }
    });
});


//forget password route
//=======forgot password======

//render form for reset
app.get("/forgot",function(req, res) {
   res.render("forgot"); 
});

//=reset mechanism to send mail to the email id===
app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: 'yelpcamp12@gmail.com',
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'TODO App',
        subject: 'TODO app Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        console.log('mail sent');
        req.flash('success', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});
//====reset link for reseting the password renders the form====
app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {token: req.params.token});
  });
});
//===post the reset change password and login user=====
app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        if(req.body.password === req.body.confirm) {
          user.setPassword(req.body.password, function(err) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpires = undefined;

            user.save(function(err) {
              req.logIn(user, function(err) {
                done(err, user);
              });
            });
          });
        } else {
            req.flash("error", "Passwords do not match.");
            return res.redirect('back');
        }
      });
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: 'yelpcamp12@gmail.com',
          pass: process.env.GMAILPW
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'yelpcamp12@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

//==================//


app.get("/logout",function(req, res) {
   req.logout(); 
   res.redirect("/"); 
});

//-===============================-//
app.listen(process.env.PORT,process.env.IP,function(){
   console.log("Server started"); 
});