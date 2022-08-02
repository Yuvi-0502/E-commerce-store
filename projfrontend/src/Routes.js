import React from 'react'
import { BrowserRouter,Route,Routes} from 'react-router-dom'
import Contact from './Contact/Contact'
import  Home from "./comp/Home";
import SignIn from './Authorization/SignIn';
import Signup from './Authorization/SignUp';
 export default function Rout(){
    return (
        
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home/>} />
        <Route path="/signin" element={<SignIn/>} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/contact" element={<Contact/>} />
      </Routes>
    </BrowserRouter>

    
    )
}
