import React, { useState, useEffect } from 'react';
import axios from 'axios';

const Mailbox = ({ token }) => {
  const [mails, setMails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchMails = async () => {
      try {
        const response = await axios.get('http://localhost:8080/mails', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        setMails(response.data || []);
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch emails');
        setLoading(false);
        setMails([]);
      }
    };

    fetchMails();
  }, [token]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div className="alert alert-danger">{error}</div>;
  if (mails === null) return <div>Loading...</div>;

  return (
    <div className="mailbox">
      <h2>Your Emails</h2>
      {mails.length === 0 ? (
        <p>No emails found</p>
      ) : (
        <div className="list-group">
          {mails.map((mail) => (
            <div key={mail.id} className="list-group-item">
              <h5>{mail.subject}</h5>
              <p>From: {mail.from}</p>
              <p>{mail.textBody.substring(0, 100)}...</p>
              <small className="text-muted">{new Date(mail.date).toLocaleString()}</small>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Mailbox;