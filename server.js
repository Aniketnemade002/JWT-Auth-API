

const fs = require('fs')
const bodyParser = require('body-parser')
const jsonServer = require('json-server')
const jwt = require('jsonwebtoken')

const server = jsonServer.create()
const router = jsonServer.router('./db.json') // Database for other routes
const userdb = JSON.parse(fs.readFileSync('./users.json', 'UTF-8')) // Load users from users.json




const SECRET_KEY = '123456789'

const expiresIn = '1h'

server.use(bodyParser.json())

// Create a token from a payload 
function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn })
}

// Verify the token 
function verifyToken(token){
  return  jwt.verify(token, SECRET_KEY, (err, decode) => decode !== undefined ?  decode : err)
}

// Check if the user exists in database
function isAuthenticated({email, password}){
  return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1
}

// Register New User
server.post('/auth/register', (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const {email, password} = req.body;

  if(isAuthenticated({email, password}) === true) {
    const status = 401;
    const message = 'Email and Password already exist';
    res.status(status).json({status, message});
    return
  }

      fs.readFile("./users.json", (err, data) => {  
         console.log("Call 1");
    if (err) {
      const status = 401
      const message = err
      res.status(status).json({status, message})
      return
    };

    // Get current users data
    console.log("Call 2");
    var data = JSON.parse(data.toString());

    // Get the id of last user
    console.log("Call 3");
    var last_item_id = data.users[data.users.length-1].id;

    //Add new user
    console.log("Call 4");
    data.users.push({id: last_item_id + 1, email: email, password: password}); 
    console.log("Call 5");
    //add some data
    var writeData = fs.writeFile("./users.json", JSON.stringify(data), (err, result) => {  // WRITE
      console.log("Call 6");
        if (err) {
          const status = 401
          const message = err
          res.status(status).json({status, message})
          return
        }else{

         const status = 200
          const message = "Registration Successful."
          res.status(status).json({status, message})
          return


        }
    });
});});


server.post('/test', (req, res) => {
   console.log(req.body);
   res.send('Request body logged in console');
 });
 




 
// Login to one of the users from ./users.json
server.post('/auth/login', (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const {email, password} = req.body;
  if (isAuthenticated({email, password}) === false) {
    const status = 401
    const message = 'Incorrect email or password OR User_DoseNot_Exist'
    res.status(status).json({status, message})
    return
  }
  const token = createToken({email, password})
  const refreshToken = jwt.sign({email, password}, SECRET_KEY, { expiresIn  });


  console.log("Access Token:" +  token);
  


  res.status(200).json({token,refreshToken})
})


//Refresh Tockern
server.post('/token', (req, res) => {
   const { refreshToken } = req.body;
 
   if (!refreshToken) {
     return res.status(401).json({ message: 'Refresh token required' });
   }
 
   try {
     const decoded = jwt.verify(refreshToken, SECRET_KEY);
     const newToken = jwt.sign({email, password }, SECRET_KEY, { expiresIn: JWT_EXPIRY });
 
     res.json({ token: newToken });
   } catch (error) {
     res.status(403).json({ message: 'Invalid refresh token' });
   }
 });









server.use(/^(?!\/auth).*$/,  (req, res, next) => {
  
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
 
    const status = 401
    const message = 'Error in authorization format'
    res.status(status).json({status, message})
    return
  }
  try {
    let verifyTokenResult;
    verifyTokenResult  = verifyToken(req.headers.authorization.split(' ')[1]);
     console.log(verifyTokenResult)
     if (verifyTokenResult instanceof Error) {
       const status = 401
       const message = 'Access token not provided'
       res.status(status).json({status, message})
       return
     }
     next()
  } catch (err) {
    const status = 401
    const message = 'Error access_token is revoked'
    res.status(status).json({status, message})
  }
})

server.use(router)

server.listen(8000, () => {
  console.log('Run Auth API Server')
})




