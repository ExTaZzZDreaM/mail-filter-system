import axios from 'axios';

const API_BASE_URL = 'http://localhost:8080';

export const register = async (userData) => {
  return axios.post(`${API_BASE_URL}/register`, userData);
};

export const login = async (credentials) => {
  return axios.post(`${API_BASE_URL}/auth`, credentials);
};

export const getMails = async (token) => {
  return axios.get(`${API_BASE_URL}/mails`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
};

export const isAdmin = async(token) => {
  return axios.get(`${API_BASE_URL}/is_admin`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
}

export const getInactiveUsers = async (token) => {
  return axios.get(`${API_BASE_URL}/inactive`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });
};

export const updateUserStatus = async (token, username) => {
  return axios.post(
    `${API_BASE_URL}/update-status`,
    { username },
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );
};