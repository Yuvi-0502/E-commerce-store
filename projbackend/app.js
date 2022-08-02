
require("dotenv").config({path:'./.env'});
const mongoose = require('mongoose');

const express=require('express');
const bodyparser=require('body-parser');
const cookieparser=require('cookie-parser');
const cors=require('cors');
const app=express()


//My routes
const authRoutes=require("./routes/authentication")
const userRoutes=require('./routes/user')
const categoryRoutes=require('./routes/category')
const productRoutes=require('./routes/product')
const orderRoutes=require("./routes/order")
const paymentBRoutes=require("./routes/paymentBRoutes")
const contactRoutes=require("./routes/contact")
mongoose.connect(process.env.DATABASE).then(() => {
    console.log("DB connection");
})
//MiddleWares
app.use(bodyparser.json())
app.use(cookieparser())
app.use(cors())

//My Routes
app.use("/api",authRoutes)
app.use("/api",userRoutes)
app.use("/api",categoryRoutes)
app.use("/api",productRoutes)
app.use("/api",orderRoutes)
app.use("/api",paymentBRoutes);
app.use("/api",contactRoutes)

//Port
const port =process.env.PORT || 8000;

//Starting a server
app.listen(port,() => {
    console.log(`app is running at port ${port}`);
})