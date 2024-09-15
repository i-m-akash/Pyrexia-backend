// const mongoose = require("mongoose");

// const userSchema = new mongoose.Schema({
//     googleId:String,
//     displayName:String,
//     email:String,
//     image:String
// },{timestamps:true});


// const userdb = new mongoose.model("users",userSchema);

// module.exports = userdb;

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    password: { type: String },
    verifiedUser: { type: Boolean, required:true ,default:false },
    googleId: { type: String },
    displayName: { type: String },
    image: { type: String },
});


 const User = mongoose.model('User', userSchema);

 module.exports = User;