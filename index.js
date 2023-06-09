require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const port = process.env.PORT || 3000;
const app = express();

const Joi = require("joi");
const expireTime = 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

const bcrypt = require('bcrypt');
const saltRounds = 12;


/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET; // generated my own guid 

const node_session_secret = process.env.NODE_SESSION_SECRET; // generated my own guid 
/* END secret section */

var { database } = include('databaseconnection');

const userCollection = database.db(mongodb_database).collection('users');

//sets the view engine for a Node.js application to EJS 
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/2537Assign1`, // keep eye on this
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessages", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/', (req, res) => {

    //   var html = `
    //     <h1>Welcome to my site</h1>
    //     <p>Please sign up or log in</p>
    //     <ul>
    //       <li><a href="/signup">Sign up</a></li>
    //       <li><a href="/login">Log in</a></li>
    //     </ul>
    //   `;
    res.render("index");
}
);

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ name: username }).project({ name: 1, password: 1, email: 1, _id: 0 }).toArray();

    console.log(result);

   // res.send(`<h1>Hello ${username}</h1>`);
});


app.get('/signup', (req, res) => {
    res.render("signup");
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var password = req.body.password;
    var email = req.body.email;

    if (!name || !email || !password) {
        var missingFields = [];
        if (!name) missingFields.push("name");
        if (!email) missingFields.push("email");
        if (!password) missingFields.push("password");

        // var htmlText = "<h1>The following fields are missing:</h1><br>";
        // missingFields.forEach(field => {
        //     htmlText += "- " + field + "<br>";
        // });
        // htmlText += "<br><a href='/signup'>Try again</a>";
        // res.send(htmlText);
        if (missingFields.length > 0) {
            const data = { missingFields };
            res.render('submituser', data);
        }
    } else {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            name: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

        const validationResult = schema.validate({ name, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/Signup");
            return;
        } else {
            var hashedPassword = await bcrypt.hash(password, saltRounds);

            await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });
            console.log("Inserted user");
            req.session.email = email;
            req.session.name = name; // add this line to store the user's name
            req.session.password = password;
            req.session.cookie.maxAge = expireTime;
            res.redirect("/members");
        }
    }
});


app.get('/login', (req, res) => {

    res.render("login");
});

app.post('/logingin', async (req, res) => {
    var password = req.body.password;
    var email = req.body.email;
    console.log(email);
    console.log(password);

    //var name = reg.body.name;
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ password: 1, email: 1, name: 1, user_type: 1, _id: 0 }).toArray();

    //user and password combination not found
    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = result[0].name; // add this line to store the user's name
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/loginSubmit");
        return;
    }
});

//user and password combination not found page
app.get('/loginSubmit', (req, res) => {
    res.render("loginSubmit");
});


app.use('/members', sessionValidation);
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    // var memeId = Math.floor(Math.random() * 3) + 1; // generate a random number between 1 and 3
    // var memeUrl = `/${memeId}.jpg`;
    const images = [
        '1.jpg',
        '2.jpg',
        '3.jpg'
    ];

    var name = req.session.name;
   // console.log(req.session.name);
    // var html = `
    //     <h1>Hello, ${name}</h1>
    //     <p>Here's your meme for the day:</p>
      
    //     <form action="/logout" method="POST">
    //         <button type="submit">Logout</button>
    //     </form>
    // `;
    res.render("members", {images, name});
});

app.get('/members/info', (req,res) => {
    res.render("members-info");
});


app.use('/admin', sessionValidation, adminAuthorization);

app.get('/admin', async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id:1, user_type: 1}).toArray();
res.render("admin", {users: result});
});

app.post('/updateUserType/:name', async (req,res) => {
    const userId = req.params.userId;
    const userType = req.body.userType;
    const name = req.params.name;
    await userCollection.updateOne({ name: name}, {$set: {user_type: userType}});
    res.redirect('/admin');
})


app.post('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});


app.use(express.static(__dirname + "/public"));

//catches all the invalid pages and send status code
app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 