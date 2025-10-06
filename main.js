const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const csurf = require('csurf');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const Sequelize = require('sequelize');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const app = express();

app.use(express.urlencoded({ extended: false }));
app.use(helmet());

app.use(expressLayouts);
app.set('layout', 'layout');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.static("public"));

app.use(session({
    secret: 'veryStrongSecretChangeMe',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: false, maxAge: 30 * 60 * 1000 }
}));

app.use(csurf());

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'secure_app.sqlite'
});

const User = sequelize.define('user', {
    email: { type: Sequelize.STRING, unique: true },
    password: Sequelize.STRING
});
sequelize.sync();

function escape(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}
app.get("/",(req,res)=>{
    res.render("open",{ csrfToken: req.csrfToken(), errors: [] });
})

app.get('/signup', (req, res) => {
    res.render('signup', { csrfToken: req.csrfToken(), errors: [] });
});

app.post('/signup',
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('signup', { csrfToken: req.csrfToken(), errors: errors.array() });
        }
        const { email, password } = req.body;
        try {
            const hash = await bcrypt.hash(password, 12);
            await User.create({ email, password: hash });
            res.redirect('/login');
        } catch {
            res.render('signup', {
                csrfToken: req.csrfToken(),
                errors: [{ msg: 'Email already registered' }]
            });
        }
    }
);

app.get('/login', (req, res) => {
    res.render('login', { csrfToken: req.csrfToken(), errors: [] });
});

app.post('/login',
    body('email').isEmail().normalizeEmail(),
    body('password').exists(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.render('login', { csrfToken: req.csrfToken(), errors: errors.array() });
        }
        const { email, password } = req.body;
        const user = await User.findOne({ where: { email } });
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.render('login', {
                csrfToken: req.csrfToken(),
                errors: [{ msg: 'Invalid credentials' }]
            });
        }
        req.session.user = { id: user.id, email: user.email };
        res.redirect('/profile');
    }
);

app.get('/profile', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.render('profile', { email: escape(req.session.user.email) });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

app.listen(3000, () => console.log('Secure Express app on 3000'));
