const express=require('express')
const router=express.Router();
const {isSignedIn,isAuthenticate}=require("../controllers/auth")
const {getToken,processPayment}=require('../controllers/paymentb')

router.get("/payment/gettoken/:userId",isSignedIn,isAuthenticate,getToken)

router.post("/payment/braintree/:userId",isAuthenticate,isSignedIn,processPayment)


module.exports=router;