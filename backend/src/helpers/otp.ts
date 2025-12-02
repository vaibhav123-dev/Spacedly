import crypto from 'node:crypto';

export const generateOTP = () => {
  return crypto.randomInt(100000, 999999).toString();
};

export const otpTemplate = (otp) => {
  return `
    <div style="font-family: Arial; padding:20px;">
      <h2>Your Verification Code</h2>
      <p>Your OTP for login is:</p>
      <h1 style="color:#2C7BE5;">${otp}</h1>
      <p>This OTP is valid for <strong>5 minutes</strong>.</p>
      <p>If you did not request this, please ignore this email.</p>
    </div>
  `;
};
