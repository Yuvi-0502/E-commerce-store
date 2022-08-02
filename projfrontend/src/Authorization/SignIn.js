import React, { useState } from "react";
import { API } from "../backend";
import Base from "../comp/Base";
import { Redirect,Navigate } from "react-router-dom";
import { isAutheticated } from "./index.js";

import {signin,authenticate} from "./index.js"

const SignIn = () => {
  const [values, setValues] = useState({
    email: "",
    password: "",
    error: "",
    loading: false,
});

  const { email, password, error, loading } = values;
  

  const handleChange = name => event => {
    setValues({ ...values, error: false, [name]: event.target.value });
  };

  const onSubmit = event => {
    event.preventDefault();
   // console.log("jai ho");
    //console.log(API);
    setValues({ ...values, error: false, loading: true });
    signin({ email, password })
      .then(data => {
        if (data.error) {
          setValues({ ...values, error: data.error, loading: false });
        } else {
          authenticate(data, () => {
            setValues({
              ...values,
  
            });
          });
        }
      })
      .catch(console.log("signin request failed"));
  };

  
  const performRedirect=()=>{
    if(isAutheticated()){
      return <Navigate to="/" />;
  }
  } 
  // const loadingMessage = () => {
  //   return (
  //     loading && (
  //       <div className="alert alert-info">
  //         <h2>Loading...</h2>
  //       </div>
  //     )
  //   );
  // };

  const errorMessage = () => {
    return (
      <div className="row">
        <div className="col-md-6 offset-sm-3 text-left">
          <div
            className="alert alert-danger"
            style={{ display: error ? "" : "none" }}
          >
            {error}
          </div>
        </div>
      </div>
    );
  };

  const signInForm = () => {
    return (
      <div className="row">
        <div className="col-md-6 offset-sm-3 text-left">
          <form>
            <div className="form-group">
              <label className="text-light">Email</label>
              <input
                onChange={handleChange("email")}
                value={email}
                className="form-control"
                type="email"
              />
            </div>

            <div className="form-group">
              <label className="text-light">Password</label>
              <input
                onChange={handleChange("password")}
                value={password}
                className="form-control"
                type="password"
              />
            </div>
            <button onClick={onSubmit} className="btn btn-success btn-block">
              Submit
            </button>
          </form>
        </div>
      </div>
    );
  };

  return (
    <Base title="Sign In page" description="A page for user to sign in!">
      {/* {loadingMessage()} */}
      {errorMessage()}
      {signInForm()}
      {performRedirect()}
      

      <p className="text-dark text-center">{JSON.stringify(values)}</p>
    </Base>
  );
};

export default SignIn;