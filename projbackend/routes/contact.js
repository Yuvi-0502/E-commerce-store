var express=require('express');
var router=express.Router();
const {contactUs} = require( "../controllers/contact")
router.post("/contact",contactUs);


module.exports=router;