const express=require('express')
const router=express.Router()

const {getCategoryById,createCategory,getAllCategory,getCategory,updateCategory,removeCategory}=require("../controllers/category")
const {isSignedIn,isAdmin,isAuthenticate}=require("../controllers/auth")
const {getUserById}=require("../controllers/user")


router.param("userId",getUserById)
router.param("categoryId",getCategoryById);

//actual routers goes here

//create Routes
router.post("/category/create/:userId",isSignedIn,isAdmin,isAuthenticate,createCategory);


//read routes
router.get("/category/:categoryId",getCategory)
router.get("/categories",getAllCategory)

//update routes
router.put("/category/:categoryId/:userId",isSignedIn,isAdmin,isAuthenticate,updateCategory)

//delete route
router.delete("/category/:categoryId/:userId",isSignedIn,isAdmin,isAuthenticate,removeCategory)

module.exports=router;