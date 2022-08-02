const express=require('express')
const router=express.Router()

const {getProductById,createProduct,getProduct, photo,deleteProduct,updateProduct,getAllProducts,getAllUniqueCategories}=require("../controllers/product")
const {isSignedIn,isAdmin,isAuthenticate}=require("../controllers/auth")
const {getUserById}=require("../controllers/user")

//all of params
router.param("userId",getUserById)
router.param("productId",getProductById)


//all routes are here

//create routes
router.post("/product/create/:userId",isSignedIn,isAdmin,isAuthenticate,createProduct)


//read routes
router.get("/product/:productId",getProduct)
router.get("/product/photo/:productId",photo)

//update routes
router.put("/product/:productId/:userId",isSignedIn,isAdmin,isAuthenticate,updateProduct)



//delete routes
router.delete("/product/:productId/:userId",isSignedIn,isAdmin,isAuthenticate,deleteProduct)

//listing routes
router.get("/products",getAllProducts);

router.get("/products/categories",getAllUniqueCategories)
module.exports=router;