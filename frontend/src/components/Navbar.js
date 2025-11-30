import React from 'react';
import { Link } from 'react-router-dom';

const Navbar = ({ token, isAdmin, onLogout }) => {
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-dark">
      <div className="container-fluid">
        <Link className="navbar-brand" to="/">Mail Client</Link>
        <div className="navbar-nav">
          {!token ? (
            <>
              <Link className="nav-link" to="/login">Login</Link>
              <Link className="nav-link" to="/register">Register</Link>
            </>
          ) : (
            <>
              <Link className="nav-link" to="/mails">Mailbox</Link>
              {isAdmin && (
                <>
                  <Link className="nav-link" to="/blocked-mails">Blocked Mails</Link>
                  <Link className="nav-link" to="/user-validation">User Validation</Link>
                </>
              )}
              <button className="nav-link btn btn-link" onClick={onLogout}>Logout</button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;