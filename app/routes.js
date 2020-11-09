var connectionParameters = require("./connection");
var connection = require('express-myconnection');
var mysql = require('mysql');
var bcrypt = require('bcrypt');
var bodyParser = require('body-parser');
var passport = require('passport');
var path = require("path");
require('../config/passport')(passport);
var urlencodedParser = bodyParser.urlencoded({ extended: true });
async = require('async');
var express = require('express');
var app = express();
var session = require('express-session');
var server = require('http').createServer(app);
var Recaptcha = require('express-recaptcha').RecaptchaV3;
var recaptcha = new Recaptcha('SITE_KEY', 'SECRET_KEY', { callback: 'cb' });
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
var nodemailer = require('nodemailer');
const fs = require('fs');
const convert = require('xml-js');
const rateLimit = require("express-rate-limit");
//const xss = require('xss-clean');
const dns = require('dns');
app.disable('x-powered-by');
compression = require('compression');
const { Resolver } = require('dns');
const resolver = new Resolver();
resolver.setServers(['4.4.4.4']);
const dnsPromises = dns.promises;


const createAccountLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 1 hour window
    max: 1000, // start blocking after 5 requests
    message:
        "Too many request created from this IP, please try again later."
});


var mysqlPool = mysql.createPool({
    host: connectionParameters[0].host,
    user: connectionParameters[0].user,
    password: connectionParameters[0].password,
    database: 'infosec',
    connectionLimit: 500
});


module.exports = function (app) {
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: '*****',
            pass: '******'
        }
    });
    var mailOptions = {
        from: '*****',
        to: '*****',
        subject: 'Sending Email using Node.js',
        text: 'Server was down and restarted. Check the error for further details!'
    };

    app.use(passport.session()); // persistent login sessions

      
        }
		



	
app.get("/", (req, res) => {					
			res.render("index")
});


    function uniqid(a = "", b = false) {
        var c = Date.now() / 1000;
        var d = c.toString(16).split(".").join("");
        while (d.length < 14) {
            d += "0";
        }
        var e = "";
        if (b) {
            e = ".";
            var f = Math.round(Math.random() * 100000000);
            e += f;
        }
        return a + d + e;
    }

  
    // Sign in & Distributing users to different pages based on their roles ================================
 app.post('/login', createAccountLimiter, function (req, res, next) {	
        passport.authenticate('local-login', function (err, user, info) {
            if (err) { return next(err); }
			
            if (!user) {
                var messages = [];
                tokenValidated = false;
                messages.push('Invalid username or password')
                return res.render('login', {                 
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
               
            });
        })(req, res, next);

    });

  
    app.get('/login2', isLoggedIn, function (req, res) {
        console.log(req.session.passport.user.qr_code);
        if (req.session.passport.user.email === null) {
            return res.redirect('email_register');
        }
        if (req.session.passport.user.password_changed == "0") {
            return res.render("password_reset_redirect", { title: "Password Reset" });
        }
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
                secret: req.session.passport.user.qr_code,//'JBVTSNTBONOTQXLFMN5EK2LHJ4UHMSKHLMVFE3KJJR5V4VSY' ,//secret.base32,
                encoding: 'base32',
            });            
            return res.render('login2', {                
                title: 'Two Factor Authentication'
            });
        }
    });

    app.post('/login2', createAccountLimiter, isLoggedIn, function (req, res) {
        var token = req.body.token; // for testing I am just sending token to front-end. send this token with /verify POST request
        // Verify a given token 
        var tokenValidates = speakeasy.totp.verify({
            secret: req.session.passport.user.qr_code,
            encoding: 'base32',
            token: req.body.token,  //token is what created in get('/') request
            window: 0
        });
		
		
		
		
        if (tokenValidates) {
        mysqlPool.getConnection(function (err, db) {
                if (err) console.log(err);
                db.query("update users2 set qr_valid=1 where id=?", [req.session.passport.user.id], function (err) {
                    if (err) { console.log(err) }
                    if (req.session.passport.user.department == "Peel9" || req.session.passport.user.department == "Demo") {
                        res.redirect('/peel9Diverter');
                    }
                    else {
                        res.redirect(`/${department(req.session.passport.user.department).path}/user_dashboard`);
                    }
                });
                db.release();
            });
        }
        else {
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

    // SAME AS LOGIN2
    app.get('/login_authenticated', isLoggedIn, function (req, res) {
        var token = speakeasy.totp({
            secret: req.session.passport.user.qr_code,
            encoding: 'base32',
        });
        res.render('/login2', {          
            title: 'Two Factor Authentication'
        });
    });
	
    app.get('/two_factor_register', isLoggedIn, newQR, function (req, res) {
        var secret = speakeasy.generateSecret({ length: 30 });
        var url = speakeasy.otpauthURL({
            secret: secret.base32,
            label: req.session.passport.user.username,
            issuer: 'InfoSEC',
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

    app.post('/qr_code_register', isLoggedIn, newQR, function (req, res) {
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

    function generateToken(n) {
        var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZVEDAT0123456789';
        var token = '';
        for (var i = 0; i < n; i++) {
            token += chars[Math.floor(Math.random() * chars.length)];
        }
        return token;
        // This Clark Reis
    }

    app.get('/email_register', isLoggedIn, newEmail, function (req, res) {
        req.session.token = generateToken(6);

        return res.render('email_register', {
            title: 'New Email',
            layout: 'layout_emty.hbs',
            secret: 'hey',
            email_entered: false
        });
    });

    app.post('/email_register', isLoggedIn, newEmail, function (req, res) {

        if (req.body.token == undefined) {
            mysqlPool.getConnection(function (err, db) {
                if (err) throw err;
                db.query("SELECT * FROM users2 WHERE email = ?", [req.body.email.trim()], function (err, rows) {
                    var messages = [];
                    if (err) throw err;
                    db.release();
                    if (rows.length) {
                        messages.push('This email is already in our system.');
                        return res.render('email_register', {
                            title: 'New Email',
                            layout: 'layout_emty.hbs',
                            secret: 'hey',
                            email_entered: false,
                            messages: messages,
                            hasErrors: messages.length > 0
                        });
                    }
                    else {
                        req.session.email = req.body.email.trim();
                        req.session.token = generateToken(6);
                        let mailOptions = {
                            from: '*****',
                            to: req.session.email,
                            subject: "Email Verification",
                            html: `
                            <!doctype html>
                            <html>
                            <body>
                                <div id="container">
                                    <h1>Email Verification: </h1>
                                    <hr>
                                    <br>
                                    <label>Your Token: </label>
                                    <h2>${req.session.token}</h2>
                                </div>
                            </body>
                            `
                        }
                        transporter.sendMail(mailOptions, function (err, info) { if (err) console.log(err); });
                        return res.render('email_register', {
                            title: 'New Email',
                            layout: 'layout_emty.hbs',
                            secret: 'hey',
                            email_entered: true
                        });
                    }
                });
            });
        }
        if (req.body.token != undefined) {
            if (req.body.token == "NULL") {
                req.session.token = generateToken(6);
                let mailOptions = {
                    from: '*****t',
                    to: req.session.email,
                    subject: "Email Verification",
                    html: `
                    <!doctype html>
                    <html>
                    <body>
                        <div id="container">
                            <h1>InfoSEC Email Verification: </h1>
                            <hr>
                            <br>
                            <label>Your Token: </label>
                            <h2>${req.session.token}</h2>
                        </div>
                    </body>
                    `
                }
                transporter.sendMail(mailOptions, function (err, info) { if (err) console.log(err); });
                return res.render('email_register', {
                    title: 'New Email',
                    layout: 'layout_emty.hbs',
                    email_entered: true
                });
            }
            if (req.session.token == req.body.token.trim()) {
                mysqlPool.getConnection(function (err, db) {
                    if (err) throw err;
                    db.query("Update users2 set email = ? where id = ?",
                        [req.session.email, req.session.passport.user.id], function (err) {
                            if (err) { console.log(err); }
                        });
                    req.session.passport.user.email = req.session.email;
                    db.release();
                    req.session.token = null;
                    req.session.email = null;
                    return res.render('email_register_success');
                });
            }
            else {
                var messages = [];
                messages.push('Token invalid or expired.');
                return res.render('email_register', {
                    title: 'New Email',
                    layout: 'layout_emty.hbs',
                    secret: 'hey',
                    email_entered: true,
                    messages: messages,
                    hasErrors: messages.length > 0
                });
            }
        }
    });

   app.get('/logout', isLoggedIn, function (req, res, next) {
          mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("set sql_safe_updates=0");
            db.query("Update sessions set lastseen = ? Where session_id = ?",
                [new Date(), req.session.id]);
            db.query("update users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                if (err) { console.log(err) }
            });
            // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
            req.logout();
            req.session.destroy();
            res.redirect('/');
            db.release();
        });
    });

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
                    db.query("update users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
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

    app.get('/logout3', function (req, res, next) {
        mysqlPool.getConnection(function (err, db) {
            if (err) throw err;
            db.query("set sql_safe_updates=0");
            db.query("Update sessions set lastseen = ? Where session_id = ?",
                [new Date(), req.session.id]);
            db.query("update users2 set qr_valid=null where id=?", [req.session.passport.user.id], function (err) {
                if (err) { console.log(err) }
            });
            // db.query("Delete from users_sessions Where session_id = ?",  [req.session.id]);
            req.logout();
            req.session.destroy();
            res.redirect('/password_reset');
            db.release();
        });
    });

 

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

function newEmail(req, res, next) {
    if (req.session.passport.user.email == null) {
        return next();
    }
    res.redirect('/login2');
}

function notLoggedIn(req, res, next) {
    if (!req.isAuthenticated()) {
        return next();
    }
    else {
        res.redirect('/logged_in');
    }
}


