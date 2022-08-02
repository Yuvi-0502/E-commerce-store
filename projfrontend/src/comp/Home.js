import React,{useState, useEffect} from 'react';
import "../styles.css";
import { API } from '../backend';
import Base from "./Base";





export default function Home() {
    console.log("API IS", API)
    
    const [products,setProducts] = useState([])
    const [error,setError] = useState(false)
    const loadProduct=async()=>{
        const res=await fetch('https://fakestoreapi.com/products')
        const product =await res.json();
        setProducts(product) 
    }
    useEffect(()=>{
        loadProduct()
    },[])

    return (
        <Base title="Home Page" description="Welcome to the apna store">
            <div className='row text-center'>
               <h1 className="text-white">ALL THE PRODUCTS</h1>
               <div className='row'>
                {products.map((product,index) => {
                    return(
                        <div key={index} className="col-4 mb-4">
                            <img src={product.image} alt=""/>
                            <p>{product.title}</p>
                        </div>
                    )
                })}
               </div>
            </div>
        </Base>
    )
}