const express=require('express')
const router=express.Router();

const {isSignedIn,isAdmin,isAuthenticate}=require("../controllers/auth")
const {getUserById,pushOrderInPurchaseList}=require("../controllers/user")
const {updateStock}=require("../controllers/product")
const {getOrderById,createOrder,getAllOrders,updateStatus,getOrderStatus}=require("../controllers/order")

router.param("userId",getUserById);
router.param("orderId",getOrderById);

router.post("/order/create/:userId",isSignedIn,isAuthenticate,pushOrderInPurchaseList,updateStock,createOrder);
router.get("/order/all/:userId",isAdmin,isAuthenticate,isSignedIn,getAllOrders)
router.get("/order/status/:userId",isAdmin,isAuthenticate,isSignedIn,getOrderStatus)
router.put("/order/:orderId/status/:userId",isSignedIn,isAuthenticate,isAdmin,updateStatus)

module.exports=router;