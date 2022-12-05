const { authenticate } = require("passport")
const bcrypt = require("bcrypt")

const LocalStrategy = require("passport-local").Strategy  

function initialize(passport, getUserByEmail, getUserById){  
    const authenticateUser = async (email, password, done) => {  //loginpage has email and password line
        const user = getUserByEmail(email)  
        if(user == null) {
            return done(null, false, {message: "no user with that email"})  //done(error, user, message)
        }

        try {
            if (await bcrypt.compare(password, user.password)) {  
                return done(null, user)
            } else {
                 return done(null, false, {message: "wrong password"})
            }
        }
        catch(e) {
            return done(e)
        }
    }

    passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser) ) 
    
    passport.serializeUser((user, done) => {done(null, user.id)})  
    passport.deserializeUser((id, done) => {
       return  done(null, getUserById(id))
    }) 

}

module.exports = initialize