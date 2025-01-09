import { API_URL } from './config.js';

document.addEventListener('DOMContentLoaded', async () => {
    const userDetailsDiv = document.getElementById('user-details');
    const donationTableBody = document.getElementById('donation-table').querySelector('tbody');

    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('You must be logged in to view your dashboard');
        }

        // Fetch user information
        const userResponse = await fetch(`${API_URL}/user`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const userData = await userResponse.json();
        if (!userData.success) {
            throw new Error(userData.message);
        }

        // Display user information
        userDetailsDiv.innerHTML = `
            <p><strong>Name:</strong> ${userData.user.name}</p>
            <p><strong>Email:</strong> ${userData.user.email}</p>
        `;

        // Fetch donation history
        const donationResponse = await fetch(`${API_URL}/donations`, {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });

        const donationData = await donationResponse.json();
        if (!donationData.success) {
            throw new Error(donationData.message);
        }

        donationData.donations.sort((a, b) => new Date(b.date) - new Date(a.date));
        // Populate donation history table
        donationData.donations.forEach(donation => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(donation.date).toLocaleString()}</td>
                <td>${donation.amount.toFixed(2)}</td>
                <td>${donation.cause}</td>
                <td>${donation.card_number}</td>
                <td>${donation.transaction_id}</td>
            `;
            donationTableBody.appendChild(row);
        });

    } catch (error) {
        userDetailsDiv.innerHTML = `<p class="error">${error.message}</p>`;
        row.innerHTML = `<p class="error">${error.message}</p>`;
    }
});