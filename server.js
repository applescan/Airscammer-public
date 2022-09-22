const express = require('express');
const app = express();
const mysql = require('mysql');
const db = require('./dbConfig');
const session = require('express-session');
const path = require('path');
const { v4: uuidv4 } = require('uuid'); // uuid, To call: uuidv4();
const bodyParser = require('body-parser'); // parser middleware
const passport = require('passport');  // authentication
const MySQLStore =  require ('express-mysql-session')(session);
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const nodeMail = require("nodemailer");

//ejs template
app.set('view engine', 'ejs');

//using app.use to serve up static css files in public/assets/folder when/public link is called in ejs files
// app.use("/route", express.static("foldername"));
app.use('/public', express.static('public'));

// this is for read POST data
app.use(express.json());

app.use(express.urlencoded({
	extended: true
}));

/*Mysql Express Session*/
app.use(session({
	key: 'session_cookie_name',
	secret: 'session_cookie_secret',
	store: new MySQLStore({
        host:'localhost',
        port: 3306,
        password: '',
        user:'1234',
        database:'airscammer'
    }),
	resave: false,
    saveUninitialized: false,
    cookie:{
        maxAge:1000*60*60*24,
    }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));


const customFields={
    usernameField:'uname',
    passwordField:'pw',
};


/*Passport JS*/
const verifyCallback=(username,password,done)=>{
   
    db.query('SELECT * FROM details WHERE username = ? ', [username], function(error, results, fields) {
       if (error) 
           return done(error);

       if(results.length==0)
       {
           return done(null,false);
       }
       const isValid=validPassword(password,results[0].hash,results[0].salt);
       user={id:results[0].id,username:results[0].username,hash:results[0].hash,salt:results[0].salt};
       if(isValid)
       {
           return done(null,user);
       }
       else{
           return done(null,false);
       }
   });
}

const strategy=new LocalStrategy(customFields,verifyCallback);
passport.use(strategy);

passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  

passport.deserializeUser((userId, done) => {
    db.query('SELECT * FROM details where id = ?', [userId], (error, results) => {
      if (error) return done(error);
      if (results[0]) {
        return done(null, results[0]);
      } else {
        return done(null, false)
      }
  
    });
  });


/*middleware*/
function validPassword(password,hash,salt)
{
    var hashVerify=crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');
    return hash === hashVerify;
}

function genPassword(password)
{
    var salt=crypto.randomBytes(32).toString('hex');
    var genhash=crypto.pbkdf2Sync(password,salt,10000,60,'sha512').toString('hex');
    return {salt:salt,hash:genhash};
}


 function isAuth(req,res,next)
{
    if(req.isAuthenticated())
    {
        next();
    }
    else
    {
        res.redirect('/notAuthorized');
    }
}


function isAdmin(req,res,next)
{
    if(req.isAuthenticated() && req.user.isAdmin==1)
    {
        next();
    }
    else
    {
        res.redirect('/notAuthorizedAdmin');
    }   
}

function userExists(req,res,next)
{
    db.query('SELECT * FROM details where username=? ', [req.body.uname], function(error, results, fields) {
        if (error) 
            {
                console.log("Error");
            }
       else if(results.length>0)
         {
            res.redirect('/userAlreadyExists')
        }
        else
        {
            next();
        }
       
    });
}


app.use((req,res,next)=>{
    console.log(req.session);
    console.log(req.user);
    next();
});


//nodemailer
require('dotenv').config();
const sgMail = require('@sendgrid/mail')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

//all routing start here..

//login page
app.get('/login', (req, res, next) => {
        res.render('login')
});

//admin login page
app.get('/admin-login', (req, res, next) => {
    res.render('admin-login')
});

//login fail page
app.get('/login-failure', (req, res, next) => {
    res.render('login-failure');
});

//logout page
app.get("/logout", (req, res) => {
    req.logout(req.user, err => {
      if(err) return next(err);
      res.redirect("/");
    });
  });

// when login success go to ratings page. When fail go to login-fail page
app.post('/login',passport.authenticate('local',{failureRedirect:'/login-failure',successRedirect:'/ratings'}));

// admin login goes to add and remove resources
app.post('/admin-login',passport.authenticate('local',{failureRedirect:'/login-failure',successRedirect:'/admin-route'}));

// admin route is a page that can only be accessed by admin to add & delete resources
app.get('/admin-route',isAdmin,(req, res, next) => {
    db.query("SELECT * FROM resources", function (err, result) {
	if (err) throw err;
	console.log(result);
    res.render('admin-route', {resourcesData:result});
});
});

// not authorized
  app.get('/notAuthorized', (req, res, next) => {
    console.log("Inside get");
    res.render('notAuthorized');
});

// not authorized admin
app.get('/notAuthorizedAdmin', (req, res, next) => {
    console.log("Inside get");
    res.render('notAuthorizedAdmin');
});

// if user already exist
app.get('/userAlreadyExists', (req, res, next) => {
    console.log("Inside get");
    res.render('userAlreadyExists');
});

//details page
app.get('/details', (req, res, next) => {
    console.log("Inside get");
    res.render('details')
});

//index page
app.get('/', function (req, res) {
	res.render("index");
});

//flight option page
app.get('/flight', function (req, res,) {
	res.render('flight');
});

//about page
app.get('/about', function(req, res) {
	res.render('about');
});

//contact page
app.get('/contact', function(req, res) {
	res.render('contact');
});

//resources page
app.get('/resources', function(req, res){
	db.query("SELECT * FROM resources", function (err, result) {
		if (err) throw err;
		console.log(result);
		res.render('resources', { title: 'resources', resourcesData:result});
	});
});

//when user hits the delete button from the resources page
app.get('/delete/:id', function(req, res, next) {
    var id= req.params.id;
      var sql = 'DELETE FROM resources WHERE id = ?';
      db.query(sql, [id], function (err, data) {
      if (err) throw err;
    });
    return res.redirect('/admin-route');  
  });

//ratings page displays the retrieved proceesed data from home & flight page (only logged in user can access)
app.get('/ratings', isAuth,(req, res, next) => {
	db.query("SELECT * FROM airlines WHERE airline='qantas'", function (err, resultqantas) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM airlines WHERE airline='jetstar'", function (err, resultjetstar) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM airlines WHERE airline='ainz'", function (err, resultainz) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM topdestination WHERE cityTo='Auckland'", function (err, resultAuckland) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM topdestination WHERE cityTo='Wellington'", function (err, resultWellington) {
		if (err) {
			return console.log('error: ' + err.message);
		}
		db.query("SELECT * FROM topdestination WHERE cityTo='Christchurch'", function (err, resultChristchurch) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM topdestination WHERE cityTo='Queenstown'", function (err, resultQueenstown) {
		if (err) {
			return console.log('error: ' + err.message);
		}
	
		db.query("SELECT * FROM details", function (err, result) {
		if (err) throw err;
		console.log(result);
		res.render('ratings', { title: 'Ratings', qantasData: resultqantas, ainzData: resultainz, jetstarData: resultjetstar, aucklandData: resultAuckland,
		wellingtonData: resultWellington, christchurchData: resultChristchurch, queenstownData: resultQueenstown, detailsData: result, user:req.user.username
	
	});
	});
	});
	});
	});
	});
	});
	});
	});
	});


//when user insert data in the HTML from index page
app.post('/', function (req, res) {
	var abcd = req.body.cityTo;
	var bcde = req.body.cityFrom;
	console.log(req.body);
	var sql = `INSERT INTO topdestination (cityTo, cityFrom) VALUES ("${abcd}", "${bcde}")`;
	db.query(sql, function (err, result) {
		if (err) throw err;
		console.log("1 record inserted");
	});
	return res.render('flight', { errormessage: 'insert data successfuly' });
});

//when user insert data in the HTML form flight page
app.post('/flight', function (req, res) {
	var x = req.body.airline;
	console.log(req.body);
	console.log(x);
	var sql = `INSERT INTO airlines (airline) VALUES ("${x}")`;
	db.query(sql, function (err, result) {
		if (err) throw err;
		console.log("1 record inserted");
	});
	return res.render('details', { errormessage: 'insert data successfuly' });
});

//when user insert data in the HTML form details page
app.post('/details',userExists,(req,res,next)=>{
    console.log(req.body.pw);
    const saltHash=genPassword(req.body.pw);
    console.log(saltHash);
    const salt=saltHash.salt;
    const hash=saltHash.hash;
    var dog = req.body.dogName;
	var mom = req.body.momName;

    db.query('INSERT into details (username,dogName,momName,hash,salt,isAdmin) values(?,?,?,?,?,0) ', 
    [req.body.uname,dog, mom,hash,salt], function(error, results, fields) {
        if (error) 
            {
                console.log("Error");
            }
        else
        {
            console.log("Successfully Entered");
        }
       
    });

    res.redirect('/login');
});

//when user insert data in the HTML form resources page
app.post('/admin-route', function(req, res){
    var id = req.body.id;
    var source = req.body.source;
    var url = req.body.url;
    console.log(req.body);
    var sql = `INSERT INTO resources (id, source, url) VALUES ("${id}", "${source}", "${url}")`;
    db.query(sql, function (err, result) {
            if (err) throw err;
            console.log("1 record inserted");
    });
    return res.redirect('admin-route');
});

//when user fill up the contact form it will send an email using nodesender and Sendgrid API
app.post('/contact', (req, res) => {
    console.log(req);
    const msg = {
        to: `sample@gmail.com`, 
        from: 'sample@gmail.com', 
        subject: req.body.subject,
        text: `${req.body.name} send a message from ${req.body.email}:\n${req.body.message}`,
    }
    try {
        sgMail.send(msg);
        res.redirect('/contact');
      } catch (error) {
        res.send("Message Could not be Sent");
      }
 });

app.listen(process.env.PORT || 3000);
console.log('Running at Port 3000')