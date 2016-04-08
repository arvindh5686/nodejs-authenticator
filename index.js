require('./bootstrap') // Setup error handlers
let User = require('./user')

let express = require('express')
let morgan = require('morgan')
    // Add to the top of index.js
let bodyParser = require('body-parser')
let cookieParser = require('cookie-parser')
let session = require('express-session')
let passport = require('passport')
let crypto = require('crypto')
let SALT = 'P@55W0RD5@lT'
require('songbird')
let flash = require('connect-flash')
let mongoose = require('mongoose')

// Add to top of index.js with other requires
let LocalStrategy = require('passport-local').Strategy
let wrap = require('nodeifyit')

const NODE_ENV = process.env.NODE_ENV
const PORT = process.env.PORT || 8000

let app = express()

// Add in-memory user before app.listen()
let user = {
    email: 'foo@foo.com',
    password: crypto.pbkdf2Sync('aaa', SALT, 4096, 512, 'sha256').toString('hex')
}

mongoose.connect('mongodb://127.0.0.1:27017/authenticator')

passport.serializeUser(wrap(async(user) => user.email))
passport.deserializeUser(wrap(async(id) => user))

// And add the following just before app.listen
// Use ejs for templating, with the default directory /views
app.set('view engine', 'ejs')

app.use(cookieParser('ilovethenodejs')) // Session cookies
app.use(bodyParser.json()) // req.body for PUT/POST requests (login/signup)
app.use(bodyParser.urlencoded({ extended: true }))
app.use(flash())
    // In-memory session support, required by passport.session()
app.use(session({
    secret: 'ilovethenodejs',
    resave: true,
    saveUninitialized: true
}))

app.use(passport.initialize()) // Enables passport middleware
app.use(passport.session()) // Enables passport persistent sessions

passport.use(new LocalStrategy({
    usernameField: 'email',
    failureFlash: true // Enables error messaging
}, wrap(async(email, password) => {
    let user = await User.promise.findOne({ email });
    //console.log(user)
    if (email !== user.email) {
        return [false, { message: 'Invalid username' }]
    }

    let passwordHash = await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')
    if (passwordHash.toString('hex') !== user.password) {
        return [false, { message: 'Invalid password' }]
    }
    return user
}, { spread: true })))

passport.use('local-signup', new LocalStrategy({
    usernameField: 'email'
}, wrap(async(email, password) => {
    email = (email || '').toLowerCase()

    if (await User.promise.findOne({ email })) {
        return [false, { message: 'That email is already taken.' }]
    }

    let user = new User()
    user.email = email

    // Store password as a hash instead of plain-text
    user.password = (await crypto.promise.pbkdf2(password, SALT, 4096, 512, 'sha256')).toString('hex')
    return await user.save()
}, { spread: true })))

// And add your root route after app.listen
//app.get('/', (req, res) => res.render('index.ejs', {}))
// Replace existing / route with...
app.get('/', (req, res) => {
    res.render('index.ejs', { message: req.flash('error') })
})

// process the login form
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

// process the signup form
app.post('/signup', passport.authenticate('local-signup', {
    successRedirect: '/profile',
    failureRedirect: '/',
    failureFlash: true
}))

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next()
    res.redirect('/')
}
app.get('/profile', isLoggedIn, (req, res) => {
        res.render('profile.ejs', {
        	'id': req.user.id,
        	'email': req.user.email,
        	'password': req.user.password
    })
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

// start server 
app.listen(PORT, () => console.log(`Listening @ http://127.0.0.1:${PORT}`))
