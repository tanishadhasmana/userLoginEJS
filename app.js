// npm init -y, app.js in package.json, npm i express jsonwebtoken bcrypt cookie-parser, and npm i ejs---below 5 section, normal compalsary--- task is we want to save user info provided, but the password should store in hash value, not a plain text in the DB
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// to save the data inside the userData file, we need the fs module]
const fs = require('fs');


const cookieParser = require('cookie-parser');
const path = require('path');
const { log } = require('console');



app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());




app.get('/', function(req, res){
  //res.send('Home page'); //in UI
  res.render('index'); //now see the index.ejs, from views
});

// for /create, this route will hit, and we want to store data but password should be encrypted as hash value
app.post('/create', function(req, res){
  let {username,email,password, age} = req.body;
  //now bcrypt usig salt, add it with the password becomes the hash
  bcrypt.genSalt(10,(err,salt)=>{
    if(err){
      console.log(err);
    }
    else{
      bcrypt.hash(password, salt,(err, hash)=>{
        if(err){
          console.log(err);
        }
        else{
          console.log(hash);
          // if I am submitting the form, the password is converted to $2b$10$t5sPfZfqCeVh/qhz/1P9G.7A/LQbyhq5UxnKfS0InP3iG5W0YwW6S
          // now if user made, the data of user will save with the encrypted pass
          let createdUser = {
            username,
            email,
            password:hash,
            age
          };
          // now as data is comming in to obj, we convert it into strg
          let userData = JSON.stringify(createdUser) + "\n";
          // now save this data to the userData.txt file
          fs.appendFile(path.join(__dirname,"views","userData.txt"), userData,(err)=>{
            if(err){
              console.log(err);
            }
            else{
              console.log("Data saved, u can se in userData.txt file");        
            }
          });

          // now we create token, using jwt and our seceret code, and sending that token in frontend, as cookie and it saved in UI
          let token = jwt.sign({email}, "ShhhhhhSeCeReT");
          res.cookie("token", token); //making this token as cookie, and for every route it will send as token
      res.send(createdUser); //now the userdata, shown in UI, with the encrypted password
        }
      })
    }

  })

})
 
       // now when /login, route will hit it will render the, login page of EJS----to rendr that, the form method in login.ejs, should be post but here if we want to *render* the login page it should get here
       app.get('/login',function(req, res){
       res.render('login');
     });
    //  now to handle the *submission* like, someone try to login, for that we use Post method. ----we want that if usermail correcect it save to user variable, if not, we say something wrong(we didnt ever specify that pass is wrong or mail is wrong, becoz, if the hacker get to know, that oh this mail, not exist and he try with another mail), now if exist we try to see password of user in DB is hashed, and the password sending/created by the user is plain
     app.post('/login', (req, res)=>{
      const {email, password} = req.body; //taking mail, and pass which user is entering in UI

      // now we read the file, to get the user data
    fs.readFile(path.join(__dirname, "views","userData.txt"), "utf-8",function(err,data){
      if(err){
        res.send("Something went wrong!"); }
        // take users, which are save in the, userData file, and take the maching user, mail, which is trying to sign in
        const users = data.trim()
        .split("\n")
        .filter(line => line.trim() !== "")
        .map(line => JSON.parse(line));
        const user = users.find(u => u.email === email);

        // if u not finded the user with the same mail, so wrong
        if(!user){
          res.send("Something went wrong");
        }
        // if user found, compare its password, with the hashed password in the DB, so can verify if it already exists or not
        bcrypt.compare(password, user.password,function(err,result){
          if(err){
             res.send("Something went wrong");
          }
          if(!result){
             res.send("Something went wrong");
          }

          // and if matched then generate token-- becoz we send cookie to browser to save user
          const token = jwt.sign({email: user.email}, "ShhhhhhSeCeReT");
           res.cookie("token", token);
           
           res.send("You logged in successfully!");
        })
    })
     })
     
     // now a logout route--- if we go to /logout, it let direct us to home page, but we jsut have to destroy the cookie, so we cna say that,if somebody logout, the cookie becomes empty
     app.get('/logout', function(req, res){
     res.cookie("token",""); //now as token is saved as cookie, previously, it is now empty
     res.redirect("/"); //when we go /logout route, we redirected to the home page, and now cookie is not the token, it is empty
     });

          

const PORT = process.env.PORT || 3005;
app.listen(PORT,function(){
  console.log(`Server is running at http://localhost:${PORT}`);
});
