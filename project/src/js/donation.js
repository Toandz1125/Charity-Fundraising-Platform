import { API_URL } from './config.js';

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('donation-form');
    const message = document.getElementById('donation-message');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const amount = document.getElementById('amount').value;
        const cause = document.getElementById('cause').value;
        const cardNumber = document.getElementById('card-number').value;
        const password = document.getElementById('password').value;

        try {
            const token = localStorage.getItem('token');
            if (!token) {
                throw new Error('You must be logged in to donate');
            }

            const response = await fetch(`${API_URL}/donate`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ amount: parseFloat(amount), cause, cardNumber, password })
            });

            const data = await response.json();

            if (data.success) {
                message.textContent = 'Thank you for your donation! Redirecting to dashboard...';
                message.className = 'message success';
                form.reset();
                setTimeout(() => {
                    window.location.href = '/project/src/auth/dashboard.html';
                }, 1500);
            } else {
                throw new Error(data.message || 'Donation failed');
            }
        } catch (error) {
            message.textContent = error.message;
            message.className = 'message error';
        }
    });
});