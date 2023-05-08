require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const port = process.env.PORT || 3000;
const app = express();

const Joi = require("joi");
const expireTime =  60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

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

var {database} = include('databaseconnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

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

app.get('/', (req, res) => {
    
      var html = `
        <h1>Welcome to my site</h1>
        <p>Please sign up or log in</p>
        <ul>
          <li><a href="/signup">Sign up</a></li>
          <li><a href="/login">Log in</a></li>
        </ul>
      `;
      res.send(html);
    }
  );

  app.get('/nosql-injection', async (req,res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: "+username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {  
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }   

    const result = await userCollection.find({name: username}).project({name: 1, password: 1, email: 1, _id: 0}).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});
  

app.get('/signup', (req,res) => {
    var html = `
        create user:
        <form action='/submitUser' method='post'>
            <input name='email' type='text' placeholder='email'>
            <input name='name' type='text' placeholder='name'>
            <input name='password' type='password' placeholder='password'>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
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

        var htmlText = "<h1>The following fields are missing:</h1><br>";
        missingFields.forEach(field => {
            htmlText += "- " + field + "<br>";
        });
        htmlText += "<br><a href='/signup'>Try again</a>";
        res.send(htmlText);
    } else {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            name: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required()
        });

        const validationResult = schema.validate({name, email, password});
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/Signup");
            return;
        } else {
            var hashedPassword = await bcrypt.hash(password, saltRounds);

            await userCollection.insertOne({name: name, email: email, password: hashedPassword});
            console.log("Inserted user");
            req.session.email = email;
            req.session.name = name; // add this line to store the user's name
            req.session.password = password;
		    req.session.cookie.maxAge = expireTime;
            res.redirect("/members");
        }
    }
});


app.get('/login', (req,res) => {
    var html = `
    Login:
    <form action='/logingin' method='post'>
        <input name='email' type='text' placeholder='email'>
        <input name='password' type='password' placeholder='password'>
        <button>login</button>
    </form>
`;

    res.send(html);
});

app.post('/logingin', async(req,res) => {
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
	   return; }

       const result = await userCollection.find({email: email}).project({ password: 1, email: 1, name: 1, _id: 0}).toArray();
   
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
app.get('/loginSubmit', (req,res) => {
    var html = "<h1>invalid email/password combination!</h1>";
  html += "<br><a href='/login'>Try again</a>";
  res.send(html);
});



app.get('/members', (req,res) => {

    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var memeId = Math.floor(Math.random() * 3) + 1; // generate a random number between 1 and 3
    var memeUrl = `/${memeId}.jpg`;
    var name = req.session.name;
    console.log(req.session.name);
    var html = `
        <h1>Hello, ${name}</h1>
        <p>Here's your meme for the day:</p>
        <img src="${memeUrl}" style="width:250px;">
        <form action="/logout" method="POST">
            <button type="submit">Logout</button>
        </form>
    `;
    res.send(html);
});

app.post('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/login');
});
app.use(express.static(__dirname + "/public"));

//catches all the invalid pages and send status code
app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 