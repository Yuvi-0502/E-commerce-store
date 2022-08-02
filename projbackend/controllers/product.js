const Product = require("../models/product")
const formidable = require("formidable");
const _ = require("lodash")
const fs = require("fs");
const { sortBy } = require("lodash");


exports.getProductById = (req,res,next,id) => {
    Product.findById(id)
    .populate("category")
    .exec((err,product) => {
        if(err){
            return res.status(400).json({
                error: "Product not found"
            })
        }
        req.product = product;
        next();
    })
}

exports.createProduct = (req, res) =>{
    try{
    
    
       let form = new formidable.IncomingForm();
       form.keepExtensions = true;
   
       form.parse(req, (err, fields, file)=>{
           console.log('files ==>', file.photo.filepath);
           // console.log("image type: ",file);
           if(err){
               res.status(400).json({
                   error: "Image could not be saved, check size of the image"
               });
           }
           
           //Destructuring fields
           const { price, description, name, category, stock} = fields;
           
           //Checking for field for validation.
           if( !name || !description || !category || !stock || !price  ){
               return res.status(400).json({
                   error: "Please include all fields, fields cannot be empty!"
               });
           }
           
           let product = new Product(fields);
           
           console.log('Product: ', product);
           //Handling files here.
           if (file.photo) {
               if (file.photo.size > 3000000) {
                 return res.status(400).json({
                   error: "File size too big!"
                 });
               }
               console.log(file.photo.filepath)
                console.log( product.photo)
                if(!file.photo.filepath) return res.send("Please send photo")
                product.photo.contentType = file.photo.mimetype; 
               product.photo.data = fs.readFileSync(file.photo.filepath);
             }
   
           product.save((err)=>{
               if(err){
                   res.status(400).json({
                       getErr: err,
                       error: "Failed to save product!"
                   })
               }
               else{
                   return res.json(product);
               }
           })
       })
    }catch(err){
    console.log(err)
    }
   }

exports.getProduct=(req,res)=>{
    req.product.photo=undefined
    return res.json(req.product)
}

exports.photo=(req,res,next)=>{
    if(req.product.photo.data){
        res.set("Content-Type",req.product.photo.contentType)
        return res.send(req.product.photo.data)
    }
    next();
}

exports.updateProduct=(req,res)=>{
    
    let form = new formidable.IncomingForm();
        form.keepExtensions = true;
    
        form.parse(req, (err, fields, file)=>{
            console.log('files ==>', file.photo.filepath);
            // console.log("image type: ",file);
            if(err){
                res.status(400).json({
                    error: "Image could not be saved, check size of the image"
                });
            }
            
           
            //updation of product
            let product=req.product;
            product=_.extend(product,fields)
            
            console.log('Product: ', product);
            //Handling files here.
            if (file.photo) {
                if (file.photo.size > 3000000) {
                  return res.status(400).json({
                    error: "File size too big!"
                  });
                }
                console.log(file.photo.filepath)
                 console.log( product.photo)
                 if(!file.photo.filepath) return res.send("Please send photo")
                 product.photo.contentType = file.photo.mimetype; 
                product.photo.data = fs.readFileSync(file.photo.filepath);
              }
    
            product.save((err)=>{
                if(err){
                    res.status(400).json({
                        getErr: err,
                        error: "Updation fails of the product."
                    })
                }
                else{
                    return res.json(product);
                }
            })
        })
     
}

exports.deleteProduct=(req,res)=>{
    let product=req.product;
        product.remove((err,deletedproduct)=>{
            if(err){
                return res.status(400).json({
                    error:"Failed to delete a product "
                })
            }
            res.json({
                message :"Deleted successfully",
                deletedproduct
            })
        })

}


exports.getAllProducts=(req,res)=>{
    let limit=req.query.limit ? parseInt(req.query.limit):8;
    let sortBy=req.query.sortBy?req.query.sortBy:"_id";
    Product.find()
    .select("--photo")
    .populate("category")
    .sort([[sortBy,"asc"]])
    .limit(limit)
    .exec((err,products)=>{
        if(err){
            return res.status(400).json({
                error:"Not found any products. "
            })
        }
        res.json(products);
    })
}

exports.updateStock=(req,res,next)=>{
        let myOperations=req.body.order.products.map(prod=>{
            return {
                updateOne:{
                    filter:{_id:prod._id},
                    update:{$inc:{stock:-prod.count,sold:+prod.count}}
                }
            }
        })

        Product.bulkWrite(myOperations,{},(err,products)=>{
            if(err){
                return res.status(400).json({
                    error:"Bulk Operations filed"
                })
            }
           // res.send(products);
            next();
        })

}

exports.getAllUniqueCategories=(req,res)=>{

    Product.distinct("category",{},(err,cate)=>{
        if(err){
            return res.status(400).json({
                error:"No Category found. "
            })
        }
       res.json(cate);
       
    })

}

