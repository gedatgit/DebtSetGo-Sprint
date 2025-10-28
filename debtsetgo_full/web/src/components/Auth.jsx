import { useState } from "react";
import { register, login } from "../api";

export default function Auth({ setUserId }) {
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");

  const handleRegister = async () => {
    console.log("Sending register data:", {email, fullName, password});
    const res = await register({ email, fullName, password});
    console.log("Server response: ", res);
    if (res.userId) setMessage("✅ Registered!");
  };

  const handleLogin = async () => {
    
    const res = await login({ email, password });
    
    if (res.userId) {
      setUserId(res.userId);
      setMessage("✅ Logged in!");
    }
  };

  return (
    <div className="auth-wrapper">

      <div className="auth-card">
        <h2>Login / Register</h2>

        <input placeholder="Email" onChange={(e) => setEmail(e.target.value)} />
        <input placeholder="Full Name" onChange={(e) => setFullName(e.target.value)} />
        <input placeholder="Password" type="password" onChange={(e) => setPassword(e.target.value)} />

        <button onClick={handleRegister}>Register</button>
        <button onClick={handleLogin}>Login</button>

        <p>{message}</p>
      </div>
    </div>
  );
}
