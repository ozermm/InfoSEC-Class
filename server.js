var fs = require('fs-extra');
var http = require('http');
var https = require('https');
const connectionParameters = require("./app/connection");
const { constants } = require('crypto');


var options = {
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert'),
	//passphrase: "infosec" ,
    //ca: fs.readFileSync('muratozer_me.csr'),
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

var passport = require('passport');
require('./config/passport')(passport);
var flash = require('connect-flash');
var validator = require('express-validator');
var exphbs = require('express-handlebars');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
var nodemailer = require('nodemailer');
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
const xss = require('xss-clean');

var session = require('express-session');
var mysql = require('mysql');
var MySQLStore = require('express-mysql-session')(session);
var bcrypt = require('bcrypt');
var redirectToHTTPS = require('express-http-to-https').redirectToHTTPS;

var mysqlPool = mysql.createPool({
    host: connectionParameters[0].host,
    user: connectionParameters[0].user, 
    password: connectionParameters[0].password,
    database: 'infosec',
    connectionLimit: 400
});

module.exports = function (app) {
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'UCinfosec',
            pass: 'infosec2021!'
        }
    });
    var mailOptions = {
        from: '*****',
        to: '*****',
        subject: 'Sending Email using Node.js',
        text: 'Server was down and restarted. Check the error for further details!'
    };

    //app.use(passport.session()); // persistent login sessions      
        }

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
app.use(function (req, res, next) {
    res.locals.login = req.isAuthenticated();
    //res.locals.session = req.session;
    next();
});

app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use cohasErrorsnnect-flash for flash messages stored in session
app.use(xss());
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
    max: 500, // start blocking after 5 requests
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

app.get('/users', createAccountLimiter, function (req, res, err) {	
        res.render('users', {
            //csrfToken: req.csrfToken(),
            // messages: messages,
            // hasErrors: messages.length > 0,
            title: 'Users'
        });
    });
	
    app.get('/user_edit/(:id)', function (req, res, next) {
        //console.log(req.params.id);
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query("Select * from users2 where id=? ",
                [req.params.id], function (err, rows) {
                if (err) {
                    console.log(err);
                }

                //res.json(rows);


                res.render('user_edit', {
                    title: 'User Edit',                   
                    id: rows[0].id,
					first_name: rows[0].first_name,
					last_name: rows[0].last_name,
					username: rows[0].username,
					email: rows[0].email,
                    
                });
                db.release();
            });
        });
    });
	
    app.post('/user_edit', function (req, res, next) {
        //console.log(req.params.id);
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query(`update users2 set username='${req.body.username}', first_name='${req.body.first_name}', last_name='${req.body.last_name}',email='${req.body.email}' where id='${req.body.id}' `,
                [req.params.id], function (err, rows) {
                if (err) {
                    console.log(err);
                }

                //res.json(rows);

                db.release();
            });
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
                    return res.redirect('./login2');
				
                }
                // Redirect if it succeeds

                //return res.redirect('/cpd_dashboard');
            });
        })(req, res, next);

    });

    app.get('/login2', isLoggedIn, function (req, res) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
        if (ip1==undefined) {ip1='1.1.1.1'};
        if (ip==undefined) {ip1='1.1.1.1'}
console.log(req.session.passport)

        //tokenValidated=false;
        //tokenValidated.push('yeniden');
        console.log(req.session.passport.user.qr_code);
       if (req.session.passport.user.qr_code === null && req.session.passport.user.qr_code_trial <= 10) {			
            return res.redirect('two_factor_register');
        }
        else if (req.session.passport.user.qr_code === null && !(req.session.passport.user.qr_code_trial <= 10)) {
            return res.render("two_factor_register_failed", {
                title: "(2FA) Failed"
            });
        }
        else {
            var token = speakeasy.totp({
                secret: req.session.passport.user.qr_code,
                encoding: 'base32',
            });            
            return res.render('login2', {               
                title: 'Two Factor Authentication'
            });
        }
    });

    app.post('/login2', createAccountLimiter, isLoggedIn, function (req, res) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
if (ip1==undefined) {ip1='1.1.1.1'};
if (ip==undefined) {ip1='1.1.1.1'}
        var token = req.body.token; // for testing I am just sending token to front-end. send this token with /verify POST request
        // Verify a given token 
        var tokenValidates = speakeasy.totp.verify({
            secret: req.session.passport.user.qr_code,
            encoding: 'base32',
            token: req.body.token,  //token is what created in get('/') request
            window: 0
        });
		
	
        if (tokenValidates) {
            //console.log('I am valid');
            mysqlPool.getConnection(function (err, db) {
                if (err) console.log(err);
                db.query("update sna.users2 set qr_valid=1 where id=?", [req.session.passport.user.id], function (err) {
                    if (err) { console.log(err) }                  
                        res.redirect('/users');
                        
                   
                });
                db.release();
            });
        }
        else {
            if (ip != '::1') {
                var map_center=null;
                if(req.ipInfo.ll){
                 map_center = req.ipInfo.ll.toString();
                }
            //var rangim = req.ipInfo.range.toString();

            var records = [[
                ip, req.ipInfo.country, req.ipInfo.region, req.ipInfo.eu, req.ipInfo.timezone, req.ipInfo.city, map_center, req.ipInfo.metro, req.ipInfo.area, 'Failed OTP Page', 'App Server', new Date(), req.session.passport.user.username, req.session.passport.user.id, hostname,ns_name
            ]]
			setTimeout(function(){
            mysqlPool.getConnection(function (err, db) {
                if (err) throw err;
                db.query("INSERT INTO remotelogs.remote_logs (ip, country, region, eu, timezone, city, map_center, metro, area, page_name, server_name,created_date, user_name, password, hostname,ns_name) values ?",
                    [records], function (err, rows) {
                        if (err) {
                            console.log(err);
                        }
                        db.release();
                    });
            });
			},500);
            }
            var messages = [];
            tokenValidated = false;
            messages.push('Please enter a correct/valid token')
            res.render('login2', {
                //csrfToken: req.csrfToken(),
                messages: messages,
                hasErrors: messages.length > 0,
                title: 'Two Factor Authentication'
            });
        }
    });

    app.get('/api/data', function (req, res, next) {
        mysqlPool.getConnection(function (err, db) {
            if (err)
                throw err;
            db.query("SELECT id, first_name, last_name, role, username,email from users2", function (err, subjectDetails2) {
                if (err) {
                    console.log(err);
                }
                res.json(subjectDetails2);
				console.log(subjectDetails2)
                db.release();
            });
        });
    });

    app.get('/signup', function (req, res) {
        res.render('signup', {
            title: 'Signup',
            
        });
    }); 
     app.post('/signup', function (req, res) {
                var password = bcrypt.hashSync(req.body.password, 10, null);
            mysqlPool.getConnection(function (err, db) {
                if (err)
                    throw err;
                db.query("SELECT * FROM users2 WHERE username = ? or email = ?", [req.body.username, req.body.email], function (err, rows) {
                    var messages = [];
                    if (err)
                        throw err;
                    if (rows.length) {
                        messages.push(`The '${rows[0].username}' username already registered in infoSEC.`);
                        res.render('signup', {
                            username: req.body.username,
                            password: req.body.password,
                            role: req.body.role,
                            first_name: req.body.first_name,
                            last_name: req.body.last_name,
                            email: req.body.email,
                            messages: messages,
                            hasErrors: messages.length > 0
                        });
                        db.release();
                    } else {                        
                        db.query("INSERT INTO users2 (username, password, role, first_name, last_name, email) " +
                            "values (?,?,?,?,?,?)", [req.body.username, bcrypt.hashSync(req.body.password, 10, null), req.body.role, req.body.first_name, req.body.last_name, req.body.email], function (err,result) {
                            if (err) {
                                console.log(err)
                                db.release();
                            } else {                        
                                        db.release();
                                        res.render('index', {
                                            title: 'Sign Up',
                                            secret: 'hey'                                           
                                        });
                                    
                                

 
                            }

                        });

                    }
                });

            });

    });

    app.get('/two_factor_register', isLoggedIn, function (req, res) {
        var secret = speakeasy.generateSecret({ length: 30 });
        var url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: req.session.passport.user.username,
            issuer: 'infoSEC Class',
            encoding: "base32"
        });

        QRCode.toDataURL(url, function (err, data_url, label) {
            res.render('two_factor_register', {
                secret: secret.base32,
                qr_code: data_url,
                label: req.session.passport.user.username,
                qr_code_check: req.session.passport.user.qr_code,
                title: 'Two Factor Registration'
            });
        });
    });

    app.post('/qr_code_register', isLoggedIn, function (req, res) {
		console.log(req.body.kodum)
		console.log(443234423423)
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("update users2 set qr_code=? Where id=?", [req.body.kodum, req.session.passport.user.id], function (err, subjectDetails2) {
                if (err) {
                    console.log(err);
                }

                res.json(subjectDetails2);
                db.release();
            });
        });
    })

    app.get('/logout', isLoggedIn, function (req, res, next) {
        var ip = req.ipInfo.ip;
        var ip1 = null;
		if(ip){
			ip = ip.replace(/ /g,'')
			ip_parca=ip.split(',')
			ip= ip_parca[0];
			ip1=ip_parca[1];			
		}
        if (ip1==undefined) {ip1='1.1.1.1'};
        if (ip==undefined) {ip1='1.1.1.1'}

        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("set sql_safe_updates=0");
            db.query("Update sessions set lastseen = ? Where session_id = ?",
                [new Date(), req.session.id]);
            db.query("update sna.users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                if (err) { console.log(err) }
            });
            // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
            req.logout();
            req.session.destroy();
            res.redirect('/');
            db.release();
        });
    });
// Route that creates a flash message using custom middleware

    app.get('/logout2', function (req, res, next) {
        console.log('hey');
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            if (session) {
                db.query("set sql_safe_updates=0");
                db.query("Update sessions set lastseen = ? Where session_id = ?",
                    [new Date(), req.session.id]);
                //db.query("Delete from  user_sessions Where session_id = ?",
                //    [req.session.id]);
                if (req.session.passport)
                {
                    db.query("update sna.users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                        if (err) { console.log(err) }
                    });
                }
                // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
                req.logout();
                req.session.destroy();
            }
            res.redirect('/login');
            db.release();
        });
    });

app.all('/session-flash', function( req, res ) {
    req.session.sessionFlash = {
        type: 'success',
        message: 'This is a flash message using custom middleware and express-session.'
    }
    res.redirect(301, '/');
});


app.use(methodOverride('X-HTTP-Method-Override')); // override with the X-HTTP-Method-Override header in the request. simulate DELETE/PUT

app.use(express.static(__dirname + '/public')); // set the static files location /public/img will be /img for users



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
//ALTER USER 'admin'@'localhost' IDENTIFIED WITH mysql_native_password BY 'infoSec2021!?_info'

function isLoggedIn(req, res, next) {               // Express Middleware functions
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
}

function newQR(req, res, next) {
    if (req.session.passport.user.qr_code === null && req.session.passport.user.qr_code_trial <= 10) {
        return next();
    }
    res.redirect('/login2');
}