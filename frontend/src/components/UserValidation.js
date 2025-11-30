// src/components/UserValidation.js
import React, { useState, useEffect } from 'react';
import { getInactiveUsers, updateUserStatus } from '../axio';
import { toast } from 'react-toastify'; // Ensure this matches your import

const UserValidation = ({ token }) => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchInactiveUsers = async () => {
      try {
        const response = await getInactiveUsers(token);
        setUsers(response.data || []);
      } catch (err) {
        setError('Failed to fetch inactive users');
      } finally {
        setLoading(false);
      }
    };

    fetchInactiveUsers();
  }, [token]);

  const handleUpdateStatus = async (username) => {
    try {
      await updateUserStatus(token, username);
      toast.success(`Status updated for ${username}`);
      // Refresh the list
      const response = await getInactiveUsers(token);
      setUsers(response.data || []);
    } catch (err) {
      toast.error(`Failed to update status for ${username}`);
    }
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div className="alert alert-danger">{error}</div>;

  return (
    <div className="user-validation">
      <h2>Inactive Users</h2>
      {users.length === 0 ? (
        <p>No inactive users found</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Username</th>
              <th>First Name</th>
              <th>Last Name</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.username}>
                <td>{user.username}</td>
                <td>{user.first_name}</td>
                <td>{user.last_name}</td>
                <td>
                  <button
                    className="btn btn-success btn-sm"
                    onClick={() => handleUpdateStatus(user.username)}
                  >
                    Activate
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default UserValidation;