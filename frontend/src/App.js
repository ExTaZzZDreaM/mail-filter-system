import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Navigate } from 'react-router-dom';
import Register from './components/Register';
import Login from './components/Login';
import Mailbox from './components/Mailbox';
import Navbar from './components/Navbar';
import BlockedMails from './components/BlockedMails';
import UserValidation from './components/UserValidation';
import './App.css';
import axios from 'axios';


function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    if (token) {
      axios
        .get('http://localhost:8080/is_admin', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        })
        .then(() => setIsAdmin(true))
        .catch(() => setIsAdmin(false));
    } else {
      setIsAdmin(false);
    }
  }, [token]);

  const handleLogin = (newToken) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken('');
  };

  return (
    <Router>
      <div className="App">
        <Navbar token={token} isAdmin={isAdmin} onLogout={handleLogout} />
        <div className="container">
          <Routes>
          <Route path="/register" element={!token ? <Register /> : <Navigate to="/mails" />} />
            <Route path="/login" element={!token ? <Login onLogin={handleLogin} /> : <Navigate to="/mails" />} />
            <Route path="/mails" element={token ? <Mailbox token={token} /> : <Navigate to="/login" />} />
            <Route path="/" element={<Navigate to={token ? "/mails" : "/login"} />} />
            <Route path="/blocked-mails" element={token ? (isAdmin ? <BlockedMails token={token} /> : <Navigate to="/mails" />) : <Navigate to="/login" />} />
            <Route path="/user-validation" element={token ? (isAdmin ? <UserValidation token={token} /> : <Navigate to="/mails" />) : <Navigate to="/login" />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;