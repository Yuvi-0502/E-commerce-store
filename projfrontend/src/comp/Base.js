import React from 'react'
import NavBar from './NavBar';
 const Base=({
     title="My Title",
     description="My Description",
     className="bg-dark text-white p-4",
     children=""
 })=>{
    
    return (
        <div>
            <NavBar/>
            {title && (
      <div className="jumbotron bg-light text-dark text-center">
        <h2 className="display-4">{title}</h2>
        <p className="lead">{description}</p>
      </div>
      )}
      <div className={className}
        style={{ minHeight: "calc(100vh - 70px)" }}
      >{children}</div>
    <footer className="footer bg-gradient-info text-white mt-auto py-3" style={{ backgroundColor: "#4D96FF" }}>
      <div className="container-fluid  text-center pt-3">
        <h4>
          Providing excellent services <span className="text-dark">Since 2022</span> 
        </h4>
      </div>

    </footer>
        </div>
    )
}
export default Base;
