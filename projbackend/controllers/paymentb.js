const braintree = require("braintree");

const gateway = new braintree.BraintreeGateway({
  environment: braintree.Environment.Sandbox,
  merchantId: "75wbzwjnqfwbn6qq",
  publicKey: "tkxt8ppqcjcdfp4g",
  privateKey: "fe1ba5d55a4538b1635f643eb23bb574"
});

exports.getToken=(req,res)=>{

     gateway.clientToken.generate({}, (err, response) => {
        // pass clientToken to your front-end
        if(err){
            res.status(500).send(err)
        }else{
            res.send(response);
        }
      });
}

exports.processPayment=(req,res)=>{

    let nonceFromTheClient=req.body.paymentMethodNonce

    let amountFromTheClient=req.body.amount
    gateway.transaction.sale({
        amount: amountFromTheClient,
        paymentMethodNonce: nonceFromTheClient,
        
        options: {
          submitForSettlement: true
        }
      }, (err, result) => {
        if(err){
            res.status(500).send(err)
        }else{
            res.send(result)
        }
      });
    
}