var connectionParameters = require("./connection");
var connection = require('express-myconnection');
var mysql = require('mysql');
//var bcrypt = require('bcrypt');
var bodyParser = require('body-parser');
//var passport = require('passport');
var path = require("path");
//require('../config/passport')(passport);
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

    //app.use(passport.session()); // persistent login sessions      
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

 
 

function isLoggedIn(req, res, next) {               // Express Middleware functions
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/');
}
