import React,{useState} from "react";
import Base from "../comp/Base"
import {Link} from "react-router-dom"
import { signup } from "../Authorization/index";


const Signup = () => {
    
    const [values,setValues] = useState({
        name:"",
        email:"",
        lastname:"",
        password:"",
        error:"",
        success: false
    });
    

    const {name, email, lastname, password, error, success} = values


    const handleChange = name => event => {
        setValues({...values,error : false, [name]:event.target.value});
    };

    const onSubmit = event => {
        event.preventDefault();
        setValues({...values,error:false});
        signup({name, lastname, email, password})
        .then(data => {
            if(data.error){
                setValues({...values, error: data.error.msg, success: false})
            }else{
                setValues({
                    ...values,
                    name: "",
                    email:"",
                    lastname:"",
                    password:"",
                    error:"",
                    success: true
                })
            }
        })
        .catch((e) => {
            console.log('Catch', e);
        })
    }


    const signUpFrom = () => {
        return (
            <div className="row">
                <div className="col-md-6 offset-sm-3 text-left">
                    <form>
                        <div className="form-group">
                            <label className="text-light">Name</label>
                            <input className = "form-control" onChange={handleChange("name")} type="text"  value={name} />
                        </div>
                        <div className="form-group">
                            <label className="text-light">LastName</label>
                            <input className = "form-control" onChange={handleChange("lastname")} type="text"  value={lastname} />
                        </div>
                        <div className="form-group">
                            <label className="text-light">Email</label>
                            <input className = "form-control" onChange={handleChange("email")} type="email"  value={email}/>
                        </div>
                        <div className="form-group">
                            <label className="text-light">Password</label>
                            <input className = "form-control" onChange={handleChange("password")} type="password"  value={password}/>
                        </div>
                        <div className="d-grid gap-2">
                            <button onClick={onSubmit} className="btn btn-success btn-primary my-3" type="button">Submit</button>
                        </div>
                    </form>
                </div> 
            </div>
        )
    }

    const successMessage = () => {
        return (
            <div className="row">
                <div className="col-md-6 offset-sm-3 text-left">
                <div className="alert alert-success" style={{display: success?"":"none"}}>
                    New account was created successfully.Please <Link to="/signin">Login Here</Link>
                </div>
            </div>
            </div>
        )
    }

    const errorMessage = () => {
        return (
            <div className="row">
                <div className="col-md-6 offset-sm-3 text-left">
                <div className="alert alert-danger"
            style={{display: error?"":"none"}}
        >
            {error}
                </div>
            </div>
            </div>
        
        )
    }
    return(
        <Base title="Sign up page" description="A page for user to sign up!">
        {successMessage()}
        {errorMessage()}
        {signUpFrom()}
        </Base>
    )
}

export default Signup;