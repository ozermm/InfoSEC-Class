// config/passport.js

// load all the things we need
var LocalStrategy   = require('passport-local').Strategy;

// load up the user model
var mysql = require('mysql');
var bcrypt = require('bcrypt');
const connectionParameters = require("../app/connection");

//console.log(connectionParameters.user);

var mysqlPool = mysql.createPool({
    host: connectionParameters[0].host,
    user: connectionParameters[0].user, 
    password: connectionParameters[0].password,
    database : 'infosec',
    connectionLimit: 99
});

// expose this function to our app using module.exports
module.exports = function(passport) {
    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
		var sessionUser = { id: user.id, 
            username: user.username,             
            name: user.last_name + ", " + user.first_name,           
            role: user.role,
            qr_code: user.qr_code, 
            qr_code_trial: user.qr_code_trial, 
            email: user.email, 
            password_changed: user.password_changed
			}
  done(null, sessionUser)
         //console.log('serializeUser: ' + user.id);
        //done(null, user.id, user.department);
    });

    // used to deserialize the user
    passport.deserializeUser(function(sessionUser, done) {
        mysqlPool.getConnection(function(err, connection) {
            if (err) throw err;

            connection.query("SELECT * FROM users2 WHERE id = ? ", [sessionUser.id], function (err, rows) {
                // console.log(rows);
                if (!err) done(null, sessionUser);
				//console.log(sessionUser);
                //else //done(err, null);
                 //   done(err, rows[0]);

            });
            connection.release();
        });
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use(
        'local-signup',
        new LocalStrategy({
                // by default, local strategy uses username and password, we will override with email
              // usernameField : 'username',
              // passwordField : 'password',
              // passReqToCallback : true // allows us to pass back the entire request to the callback
            },
            function(req, username, password, done) {
                req.checkBody('username', 'Invalid username').notEmpty();
                req.checkBody('password', 'Invalid password').notEmpty().isLength({min:8});	
				
                var errors = req.validationErrors();
                if (errors){
                    var messages = [];
					
                    errors.forEach(function(error) {
                        messages.push(error.msg);
                    });
                    return done (null, false, req.flash('signupMessage', messages));
					
                }
                // find a user whose email is the same as the forms email
                // we are checking to see if the user trying to login already exists
                mysqlPool.getConnection(function(err, connection) {
                    if (err) throw err;
                    connection.query("SELECT * FROM users2 WHERE username = ?", [username], function (err, rows) {
                        if (err)
                            return done(err);
                        if (rows.length) {
                            return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
                        } else {
                            // if there is no user with that username
                            // create the user
                            var newUserMysql = {
                                username: username,
                                password: bcrypt.hashSync(req.body.password, 10, null)  // use the generateHash function in our user model
                            };
					

                            var insertQuery = "INSERT INTO users2 ( username, password, role, first_name, last_name, email ) values (?,?,?,?,?,?)";
                            connection.query(insertQuery, 
							[newUserMysql.username, newUserMysql.password, req.body.role, req.body.first_name, req.body.last_name, req.session.passport.user.username, req.body.email], function (err, rows) {
                                newUserMysql.id = rows.insertId;

                                return done(null, newUserMysql);
                            });
                        }

                    });
                    connection.release();
                });
            })
    );
	

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use(
        'local-login',
        new LocalStrategy({
                // by default, local strategy uses username and password, we will override with email
                usernameField : 'username',
                passwordField : 'password',
                roleField : 'role',				
                passReqToCallback : true // allows us to pass back the entire request to the callback
            },
            function(req, username, password, done) { // callback with email and password from our form
                req.checkBody('username', 'Invalid username').notEmpty();
                req.checkBody('password', 'Invalid password').notEmpty();
                var errors = req.validationErrors();
                if (errors){
                    var messages = [];
                    errors.forEach(function(error) {
                        messages.push(error.msg);
                    });
                    return done (null, false, req.flash('loginMessage', messages));
                }
                mysqlPool.getConnection(function(err, connection) {
                    if (err) throw err;
                    connection.query("SELECT * FROM users2 WHERE username = ?", [username], function (err, rows) {
                        if (err)
                            return done(err);
                        if (!rows.length) {
                            return done(null, false, req.flash('loginMessage', 'Oops! Wrong username or password.')); // req.flash is the way to set flashdata using connect-flash
                        }

						 if (rows.length) {
                            var insertQuery = "INSERT INTO sessions (session_id, username, dateseen, role, user_id) values (?,?,?,?,?)";
                                        connection.query(insertQuery, [req.session.id, rows[0].last_name + ', ' + rows[0].first_name, new Date(), 1, rows[0].department,rows[0].id]);																				
                                        console.log('successfully added to sessions database');
                        }
						
                        // if the user is found but the password is wrong
                        if (!bcrypt.compareSync(password, rows[0].password))
                            return done(null, false, req.flash('loginMessage', 'Oops! Wrong username or password.')); // create the loginMessage and save it to session as flashdata
                        // all is well, return successful user
                        return done(null, rows[0]);


                    });
                    connection.release();
                });
            })
    );
};
