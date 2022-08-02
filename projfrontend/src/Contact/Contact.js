import React,{useState} from 'react';
import '../styles.css'
import contact from "./contactimg.jpg"
import Base from '../comp/Base';
import { contactus} from '../Authorization/index';
const Contact = () => {
   
  const [values,setValues] = useState({
    name:"",
    subject:"",
    email:"",
    message:"",
    error:"",
    success:false
});
const {name, email, subject, message, error, success} = values

const handleChange = name => event => {
  setValues({...values,error : false, [name]:event.target.value});
};
  
const sendMssge=(event)=>{
    event.preventDefault();
        setValues({...values,error:false});
        //console.log(name+" "+subject+" "+email+" "+message);
        contactus({name, subject, email, message})
        .then(data => {
            if(data.error){
                setValues({...values, error: data.error.msg, success: false})
            }else{
                setValues({
                    ...values,
                    name: "",
                    subject:"",
                    email:"",
                    message:"",
                    error:"",
                    success: true
                })
            }
        })
        .catch((e) => {
            console.log('Catch', e);
        })
  }

  return (
      <Base title="Contact Us page" description="A page for contact !">
        <section id="contact" className="contact text-dark">
      <div className="container" data-aos="fade-up">

        <div className="section-title">
          <h2  style={{color:"#fff"}}>Contact Us</h2>
          {/* <p>Magnam dolores commodi suscipit. Necessitatibus eius consequatur ex aliquid fuga eum quidem. Sit sint consectetur velit. Quisquam quos quisquam cupiditate. Et nemo qui impedit suscipit alias ea. Quia fugiat sit in iste officiis commodi quidem hic quas.</p> */}
        </div>

        <div>
      <img src={contact} alt="" />
        </div>

        <div className="row mt-5">

          <div className="col-lg-4">
            <div className="info">
              <div className="address">
                <i className="bi bi-geo-alt"></i>
                <h4 style={{color:"#fff"}}>Location:</h4>
                <p style={{color:"cyan"}}>Ram Nivas,  jai Garh,Rampura</p>
              </div>

              <div className="email">
                <i className="bi bi-envelope"></i>
                <h4 style={{color:"#fff"}}>Email:</h4>
                <p><a href="mailto:yuvi0502@gmail.com">yuvi0502@gmail.com</a></p>
              </div>

              <div className="phone">
                <i className="bi bi-phone"></i>
                <h4 style={{color:"#fff"}}>Call:</h4>
                <p><a href="tel:+919509267890">9509267890</a></p>
              </div>

            </div>

          </div>

          <div className="col-lg-8 mt-5 mt-lg-0">

              <div className="row">
                <div className="col-md-6 form-group">
                  <input type="text" name="name" className="form-control" onChange={handleChange("name")} id="name" placeholder="Your Name" required/>
                </div>
                <div className="col-md-6 form-group mt-3 mt-md-0">
                  <input type="email" className="form-control" name="email" onChange={handleChange("email")} id="email" placeholder="Your Email" required/>
                </div>
              </div>
              <div className="form-group mt-3">
                <input type="text" className="form-control" name="subject" onChange={handleChange("subject")} id="subject" placeholder="Subject" required/>
              </div>
              <div className="form-group mt-3">
                <textarea className="form-control" name="message" rows="5" onChange={handleChange("message")} placeholder="Message" required></textarea>
              </div>
              {/* <div className="my-3">
                <div className="loading">Loading</div>
                <div className="error-message"></div>
                <div className="sent-message">Your message has been sent. Thank you!</div>
              </div> */}
              <div ><button className="text-center btn btn-block btn-outline-success mt-2 mb-2" type="submit" onClick={sendMssge}>Send Message</button></div>

          </div>

        </div>

      </div>
      
    </section>
    </Base >
    );
}

export default Contact;