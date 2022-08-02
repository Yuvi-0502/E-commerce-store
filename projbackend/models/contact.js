const mongoose=require("mongoose");

const contactSchema = new mongoose.Schema({
    name :{
        type: String,
        required:true,
        maxlength:32,
        trim:true,
    },
    subject:{
        type:String,
        trim:true
    },
    email:{
        type:String,
        trim:true,
        required:true,
    },
    message:{
       type:String,
       trim:false
    }
})

module.exports=mongoose.model("Contact",contactSchema);