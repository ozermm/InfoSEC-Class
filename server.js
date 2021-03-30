var fs = require('fs-extra');
var http = require('http');
var https = require('https');
const connectionParameters = require("./app/connection");
const { constants } = require('crypto');


var options = {
    key: fs.readFileSync('infoSEC.key'),
    cert: fs.readFileSync('muratozer_me.crt'),
	passphrase: "Murat2008" ,
    ca: fs.readFileSync('muratozer_me.ca-bundle'),
    secureOptions: constants.SSL_OP_NO_SSLv3 | constants.SSL_OP_NO_TLSv1,
};


var express = require('express');
var app = express();
const expressip = require('express-ip');
var getIpInfoMiddleware = function(req, res, next) {
    var client_ip;
    if (req.headers['cf-connecting-ip'] && req.headers['cf-connecting-ip'].split(', ').length) {
        var first = req.headers['cf-connecting-ip'].split(', ');
        client_ip = first[0];
    } else {
        client_ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;
    }
    req.client_ip = client_ip;
    next();
};
app.use(expressip().getIpInfoMiddleware);
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

var path = require('path');
var bodyParser = require('body-parser');
//const expressSanitizer = require('express-sanitizer');
var methodOverride = require('method-override');
var server2 = require('http').createServer(app);
var server = https.createServer(options,app);

//var passport = require('passport');
var flash = require('connect-flash');
var validator = require('express-validator');
var exphbs = require('express-handlebars');
var hbs = exphbs.create({
    helpers: {
   iff: function (a, b, options) {
    if (a == b) { return options.fn(this); }
    return options.inverse(this); },
    },
	extname: '.hbs', 
	defaultLayout: 'layout', 
	layoutsDir: __dirname + '/public/views/layouts/', 
	partialsDir: __dirname + '/public/views/partials/' 
});
var router = express.Router();
const rateLimit = require("express-rate-limit");
const helmet = require('helmet');
//const xss = require('xss-clean');

var session = require('express-session');
//var mysql = require('mysql');
//var MySQLStore = require('express-mysql-session')(session);
var redirectToHTTPS = require('express-http-to-https').redirectToHTTPS;
/*
var mysqlPool = mysql.createPool({
    host: connectionParameters[0].host,
    user: connectionParameters[0].user, 
    password: connectionParameters[0].password,
    database: 'infosec',
    connectionLimit: 400
});

var sessionStore = new MySQLStore({   
	clearExpired: true, 
	checkExpirationInterval: 900000, 
	expiration: 86400000,
	endConnectionOnClose: true, 
	charset: 'utf8mb4_bin',
    createDatabaseTable: true,
    schema: {
        tableName: 'users_sessions',
        columnNames: {
			id: 'id',
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
}, mysqlPool);
*/
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// view engine setup
app.engine('.hbs', hbs.engine);
app.set('view engine', '.hbs');
app.set('views', path.join(__dirname, 'public'));
expressValidator = require('express-validator');

var fs = require('fs');

app.use(bodyParser.json({limit: '10mb', extended: true}));
app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
app.use(bodyParser.urlencoded({limit: '10mb', extended: true})); // parse application/x-www-form-urlencoded
app.use(validator());

app.use(session({
    key: '123456',
    secret: '123456',
    //store: sessionStore,
    resave: false,
    cookie: { maxAge: 12 * 60 * 60 * 1000 }, //cookie time for 12 hours
    saveUninitialized: true
}));

app.use(helmet());

//app.use(passport.initialize());
//app.use(passport.session()); // persistent login sessions
app.use(flash()); // use cohasErrorsnnect-flash for flash messages stored in session
app.use(function(req, res, next){
    res.setTimeout(120000, function(element){
        console.error('Request has timed out in the following route -->', element._httpMessage.req.originalUrl);
            res.sendStatus(408);
        });
    next();
});

// Custom flash middleware -- from Ethan Brown's book, 'Web Development with Node & Express'
app.use(function(req, res, next){
    // if there's a flash message in the session request, make it available in the response, then delete it
    res.locals.sessionFlash = req.session.sessionFlash;
    delete req.session.sessionFlash;
    next();
});

// Route that creates a flash message using the express-flash module
app.all('/express-flash', function( req, res ) {
    req.flash('success', 'This is a flash message using the express-flash module.');
    res.redirect(301, '/');
});

const createAccountLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 1 hour window
    max: 5, // start blocking after 5 requests
    message:
        "Too many request created from this IP, please try again later."
});

app.get("/", function (req, res, err) {					
			res.render('index')
});


app.get('/login', createAccountLimiter, function (req, res, err) {	
        res.render('login', {
            //csrfToken: req.csrfToken(),
            // messages: messages,
            // hasErrors: messages.length > 0,
            title: 'Login'
        });
    });

app.post('/login', createAccountLimiter, function (req, res, next) {	
        passport.authenticate('local-login', function (err, user, info) {
            if (err) { return next(err); }
			
            if (!user) {
                var messages = [];
                tokenValidated = false;
                messages.push('Invalid username or password')
                return res.render('login', {
                    //csrfToken: req.csrfToken(),
                    messages: messages,
                    hasErrors: messages.length > 0,
                    title: 'Login'
                });
            }

            req.logIn(user, user.role, function (err) {
                //console.log(user);
                if (err) { return next(err); }
                if (user) {
                    //return res.redirect('./welcome');
					return res.render('welcome', {
                    //csrfToken: req.csrfToken(),
                    messages: messages,
                    hasErrors: messages.length > 0,
                    title: 'Login'
                });
                }
                // Redirect if it succeeds

                //return res.redirect('/cpd_dashboard');
            });
        })(req, res, next);

    });


// Route that creates a flash message using custom middleware
app.all('/session-flash', function( req, res ) {
    req.session.sessionFlash = {
        type: 'success',
        message: 'This is a flash message using custom middleware and express-session.'
    }
    res.redirect(301, '/');
});


app.use(methodOverride('X-HTTP-Method-Override')); // override with the X-HTTP-Method-Override header in the request. simulate DELETE/PUT

app.use(express.static(__dirname + '/public')); // set the static files location /public/img will be /img for users

app.use(function (req, res, next) {
    res.locals.login = req.isAuthenticated();
    // res.locals.session = req.session;
    next();
});

app.use(limiter);

app.use(redirectToHTTPS([/localhost:(\d{4})/], [/\/insecure/], 301));
require('./app/routes')(app); // pass our application into our routes
require("express-stream-json");

server2.listen(80)


server.listen(443,()=>{
console.log('server started')
})


console.log('server started'); 			// shoutout to the user
exports = module.exports = app; 						// expose app
//ALTER USER 'infosec'@'localhost' IDENTIFIED WITH mysql_native_password BY 'infosec'