import React, { useState, useEffect } from 'react';
import axios from 'axios';

const BlockedMails = ({ token }) => {
  const [blockedMails, setBlockedMails] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchBlockedMails = async () => {
      try {
        const response = await axios.get('http://localhost:8080/blocked-mails', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        const mailMap = response.data || {};
        console.log('Fetched blocked mails:', mailMap);
        const groupedMails = Object.entries(mailMap).flatMap(([cause, mails]) =>
        mails.map((mail, index) => ({
          id: mail.messageID || `${cause}-${index}`,
          cause,
          senderIP: mail.senderIP || 'Unknown',
          subject: mail.subject || '(No Subject)',
          from: mail.from || 'Unknown',
          to: mail.to || 'Unknown',
          date: mail.date ? new Date(mail.date).toLocaleString() : 'Unknown',
          attachments: mail.attachments || [],
        })))
        

        setBlockedMails(groupedMails);
      } catch (err) {
        setError('Failed to fetch blocked emails');
        setBlockedMails([]);
      } finally {
        setLoading(false);
      }
    };
    fetchBlockedMails();
  }, [token]);

  const downloadAttachment = (attachment) => {
    console.log('Attachment:', attachment);
    console.log('Data type:', typeof attachment.data);
    console.log('Data content:', attachment.data);
    console.log('Data length:', attachment.data?.length);

    if (!attachment.data) {
      alert('No attachment data available.');
      console.error('Attachment data is missing or null');
      return;
    }

    try {
      let byteArray;
      if (typeof attachment.data === 'string') {
        const binaryString = atob(attachment.data);
        byteArray = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          byteArray[i] = binaryString.charCodeAt(i);
        }
      } else if (Array.isArray(attachment.data) || attachment.data instanceof Uint8Array) {
        byteArray = attachment.data instanceof Uint8Array 
          ? attachment.data 
          : new Uint8Array(attachment.data);
      } else {
        throw new Error('Unsupported data format');
      }

      if (byteArray.length === 0) {
        alert('Attachment data is empty.');
        console.error('Decoded attachment data is empty');
        return;
      }

      const blob = new Blob([byteArray], { type: attachment.contentType || 'application/octet-stream' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = attachment.filename || 'attachment';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download attachment. The data may be corrupted or not Base64-encoded. Check console for details.');
      console.error('Attachment download error:', err);
    }
  };

  if (loading) return <div className="text-center py-4">Loading...</div>;
  if (error) return <div className="alert alert-danger m-4">{error}</div>;

  const groupedByCause = blockedMails.reduce((acc, mail) => {
    if (!acc[mail.cause]) acc[mail.cause] = [];
    acc[mail.cause].push(mail);
    return acc;
  }, {});

  return (
    <div className="blocked-mails container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-6">Blocked Emails</h2>
      {blockedMails.length === 0 ? (
        <p className="text-gray-600">No blocked emails found</p>
      ) : (
        Object.entries(groupedByCause).map(([cause, mails]) => (
          <div key={cause} className="mb-8">
            <h3 className="text-xl font-semibold text-gray-700 mb-2">Cause: {cause}</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full bg-white border border-gray-200 mb-4">
                <thead>
                  <tr className="bg-gray-100">
                    <th className="py-2 px-4 border-b text-left">Sender IP</th>
                    <th className="py-2 px-4 border-b text-left">Subject</th>
                    <th className="py-2 px-4 border-b text-left">From</th>
                    <th className="py-2 px-4 border-b text-left">To</th>
                    <th className="py-2 px-4 border-b text-left">Date</th>
                    <th className="py-2 px-4 border-b text-left">Attachments</th>
                  </tr>
                </thead>
                <tbody>
                  {mails.map((mail) => (
                    <tr key={mail.id} className="hover:bg-gray-50">
                      <td className="py-2 px-4 border-b">{mail.senderIP}</td>
                      <td className="py-2 px-4 border-b">{mail.subject}</td>
                      <td className="py-2 px-4 border-b">{mail.from}</td>
                      <td className="py-2 px-4 border-b">{mail.to}</td>
                      <td className="py-2 px-4 border-b">{mail.date}</td>
                      <td className="py-2 px-4 border-b">
                        {mail.attachments.length > 0 ? (
                          <ul className="list-disc list-inside">
                            {mail.attachments.map((attachment, index) => (
                              <li key={index}>
                                <button
                                  onClick={() => downloadAttachment(attachment)}
                                  className="text-blue-600 hover:underline"
                                  title={`Download ${attachment.filename}`}
                                >
                                  {attachment.filename || 'Unnamed attachment'}
                                </button>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          'None'
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default BlockedMails;
