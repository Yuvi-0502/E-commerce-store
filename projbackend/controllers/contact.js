const Contact=require("../models/contact")

exports.contactUs=(req,res)=>{
    const contact=new Contact(req.body)
    console.log(contact);
    contact.save((err,user) =>{
        if(err){
            return res.status(400).json({
                err :"Not able to save user information in Database"
            })
        }
        res.json({
            name:user.name,
            subject:user.subject,
            email:user.email,
            message:user.message
        })
    });
}